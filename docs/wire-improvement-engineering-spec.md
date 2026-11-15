# Engineering specification for realistic attack and defense comparison

**Status:** Proposed implementation specification, revised after implementation and design review  
**Date:** 16 November 2026  
**Implementation baseline:** `286cf02952b87b0525ee4c9cc718543f54a759cd` on `main`  
**Primary files:** [wire-engine.js](../js/wire-engine.js), [wire.html](../wire.html), [reference catalog](../assets/wire-defense-catalog.json), [model regression suite](../scripts/test-wire-model.cjs)

## 1 Purpose and design decision

Upgrade the browser simulation so it explains how conventional operator-led attacks and agentic attacks behave against plausible enterprise infrastructure, and how virtual patching, canaries and agentic SOC change their options and consequences.

The simulation must derive outcomes from **reachability, access prerequisites, attacker decisions, control coverage, observable evidence and response authority**. Preserve historically informed elapsed-time estimates as presentation context. Do not determine winners by comparing model inference speeds, sub-minute timers, animation durations or arbitrary numbers of turns.

This is a simulation engineering project. No live offensive agent, exploit execution or production SOC is required. Docker and its associated lab implementation are outside scope.

The design retains the existing wire visualization and repeatable estate concept. It replaces outcome shortcuts with an explicit model of actions, observations and interventions. It must support plausible success, failure, partial impact and unresolved outcomes for both attacker types and every defense configuration.

### Required product questions

For every run, a viewer must be able to answer:

1. What access and knowledge did the attacker start with?
2. Which weakness, permission or relationship made each successful step possible?
3. Which behavior distinguished the attacker profiles in this scenario?
4. What could each control inspect or observe, and what did it miss?
5. What did the defender conclude, what could it do, and what actually changed?
6. Was sensitive information accessed, was a decoy touched, or was there merely a reachable service?
7. Which assumptions would change the outcome?

“Must” denotes a release requirement. Numeric defaults described as illustrative must be exposed as assumptions and must not become undocumented effectiveness claims.

## 2 Critique incorporated into this revision

The earlier draft correctly proposed removing exercise bypasses, placing monitoring on the estate, adding explicit decoys and consolidating the engines. Several proposed replacements would still predetermine the comparison. This revision resolves them as follows.

| Earlier proposal or omission | Why it is insufficient | Required replacement |
| --- | --- | --- |
| ARTEX always evades signature rules; older attackers cannot adapt | Assigns success by actor identity and treats adaptation as guaranteed | Evaluate a modeled action variant against the actual rule; both profiles may adapt subject to knowledge, tools and effort. |
| Older attackers are noisy with multiplier 1.35; ARTEX is quiet with multiplier 0.65 | Hardcodes an unsupported detection advantage | Generate observations from actions and sensors. Profiles influence action selection, not a global detection multiplier. |
| Force 85% successful four-layer paths | Recreates the current presentation bias | Use explicit walkthrough fixtures and separately generated exploratory estates, including secure and partially exposed estates. |
| One versus three actions per round under a shared round limit | Gives one profile three times the action allowance and recreates a race through turn counts | Use the same total attempt and assistance budgets; represent concurrent branches separately from resource allowance. |
| Canary signal immediately contains the attacker | Conflates detection, identity attribution, response authority and successful enforcement | Route canary evidence through the same SOC decision and response model as other evidence. |
| Two crossed boundaries imply malicious activity | Legitimate workflows also cross boundaries | Require observable suspicious evidence, identity context and a stated detection hypothesis; include benign counterexamples. |
| Data breach means a non-decoy read in Layer 3 | Sensitive data can be public-facing; public content can reside internally | Evaluate named datasets and explicit objectives, independent of diagram layer. |
| Decommissioned means disconnected; proof of concept means unmonitored | Lifecycle labels alone do not establish connectivity or monitoring | Model active interfaces, routes, permissions and sensors explicitly. Remove cosmetic lifecycle suffixes. |
| Re-enable the old mitigation lookup for every SOC action | Existing booleans mix observation with instantaneous prevention | Separate patch enforcement, telemetry, incident reasoning and confirmed response. |
| Defense modes receive smaller data traversal caps | Makes defenses appear to reduce impact without an intervention | Separate rendering limits from simulation budgets and keep comparison budgets equal. |
| One global RNG stream and root-node session scope | Small setting changes scramble unrelated draws; merged routes can inherit the wrong response scope | Use stable keyed random draws and explicit principal, credential, session and host lineage. |
| Convert a published mean into a median and assumed distribution | A mean does not identify quantiles or the distribution's shape | Store the source statistic separately from any distribution chosen as a modeling assumption. |
| Make human SOC observe fewer layers and contain less than agentic SOC | Confounds reasoning policy with deployment and authority | Compare policies on equal telemetry and permissions; compare deployment differences separately and label them. |
| Require all aggregate outcomes to improve monotonically with coverage | Adaptive attackers, false interventions and changed exploration can alter downstream behavior | Check local control semantics under fixed actions, then inspect scenario sensitivity without forcing a global ranking. |

These decisions replace conflicting recommendations in earlier review documents. The earlier [realism review](artex-comparison-realism-review.md) remains supporting analysis; its response-timing and lab workstreams are not implementation requirements here.

## 3 Scope and release boundaries

### In scope

- A single deterministic simulation engine used by exploratory estates and authored scenarios.
- Coherent infrastructure archetypes, typed access relationships and explicit data objectives.
- Conventional and agentic attacker policies with knowledge limits and fallible adaptation.
- Route-specific WAF virtual patches, explicit decoys and evidence-driven SOC response.
- Independent defense switches and paired comparison on the same estate.
- Exportable scenario manifests, explainable event histories, outcome metrics and regression fixtures.
- Integration with the existing static HTML launcher and browser/Node execution model.

### Boundaries

The first release implements WAF-based virtual patching. Unsupported protocols must be reported as outside that control's scope, not as inherently immune to all forms of virtual patching. Other enforcement mechanisms can be added through the same control interface later.

The first release implements sensitive read and simulated export objectives. It can count affected assets and privileges. Encryption, persistence, destructive impact and business-loss estimates require their own action and impact models; do not infer them from a record read.

Historical durations remain editable context. The existing 80–270 minute and 45–75 minute presets may be retained only as labeled scenario assumptions until their exact displayed milestones have supporting calibration. Do not substitute other duration bands merely by equating breakout, dwell, deep access and record access. The calibration register below makes the distinction explicit. Durations must not be inputs to control success, attack eligibility or termination; changing only them must leave the causal result unchanged.

## 4 Non-negotiable model invariants

| ID | Requirement |
| --- | --- |
| R01 | Every state-changing attacker action must satisfy explicit reachability, capability and authorization or weakness prerequisites. |
| R02 | The attacker policy may use only its observations, initial knowledge and acquired capabilities; it must not inspect hidden estate findings or decoy flags. |
| R03 | The SOC policy may use only available telemetry and authorized investigation results; it must not inspect hidden attacker intent or ground-truth success. |
| R04 | Neither actor names nor diagram layers directly determine detection, patch effectiveness, canary interaction or containment. |
| R05 | Every effective defense must identify its control, evidence or rule, affected scope and state change. |
| R06 | Every canary alert must identify a deployed decoy and a matching interaction; successful authentication is not required for every trigger type. |
| R07 | A canary alert alone must not revoke access. A response proposal alone must not count as enforcement. |
| R08 | Simulation budgets must be identical across defense configurations; rendering limits must never restrict simulation state. |
| R09 | Dataset classification and objective predicates determine impact, independently of layer or public reachability. |
| R10 | Equal manifests must replay deterministically, including all decisions and reason codes. Layout and animation changes must not alter results. |
| R11 | Outcome-sensitive uncertainty must be shown as conditional or unresolved; the engine must not silently assume a favorable response order. |
| R12 | Every successful, denied, failed, suppressed or unattempted dependent action must be explainable without inventing an attack that never occurred. |
| R13 | Missing required configuration must fail validation visibly; unsupported or unknown coverage must be explicit states, never silent effectiveness defaults. |
| R14 | Displayed numbers must resolve to sourced observations, labeled assumptions or computed results with traceable input provenance. |

## 5 Target architecture and integration contracts

Keep `js/wire-engine.js` as the public facade exposed as `WireEngine` in the browser and through CommonJS in Node. Pure components may initially remain inside that file. If split into files, preserve explicit script loading and Node imports; introducing a bundler is not a prerequisite.

The engine has seven logical components:

| Component | Responsibility | Must not do |
| --- | --- | --- |
| Estate builder and validator | Instantiate archetypes, weaknesses, permissions, observations and control locations | Insert hidden success paths to hit a target breach percentage |
| Attacker policy | Select known opportunities, tools, branches and adaptations | Read undiscovered findings or force a rule bypass |
| Action evaluator | Validate prerequisites and calculate candidate world changes | Assign detection or response from the actor label |
| Observation engine | Turn actual behavior into sensor events and decoy triggers | Expose all ground truth to the SOC |
| SOC policy | Correlate, investigate, decide and propose scoped actions | Treat a high score as confirmed containment |
| Response executor | Check authority, apply supported actions and record confirmation | Revoke unrelated identities or erase completed impact |
| Result projector | Derive metrics, graph states and tickets from the event history | Manufacture compromise or containment in the DOM |

Target public functions:

```js
generateEstate({ archetypeId, estateSeed, scenarioId, generationMode })
validateEstate(estate) // { valid, errors, warnings }
validateRunConfig(estate, runConfig)
simulateScenario({ estate, attackerProfile, defenseConfig, runConfig })
evaluateComparison({ estate, attackerProfiles, defenseConfigs, runConfig })
projectRun(run, presentationConfig)
exportManifest(comparison)
importManifest(json) // validate or return an explicit compatibility error
```

`simulateScenario` must not mutate its input objects. Comparison cells receive isolated copies of mutable run state. `projectRun` receives the completed trace and may attach coarse elapsed-time labels; it cannot change the trace's outcomes.

### Execution lifecycle

1. Validate the estate and run configuration, apply the selected deployment overlay, and initialize separate world, attacker and defender state.
2. Enumerate actions from attacker knowledge and select independent candidates under the remaining attempt budget. Resolve existing confirmed controls and prerequisites before dispatch.
3. Record dispatched attempts, evaluate applicable inline rules, and commit allowed action effects. Generate observations for successful and unsuccessful behavior wherever the installed sensors can observe it.
4. Update attacker knowledge from modeled responses. Deliver available observations to the incident policy, execute authorized investigations and record any proposed responses.
5. Apply confirmed reactive effects according to the declared intervention contracts. Branch only when an unspecified ordering changes a relevant outcome. Re-evaluate affected candidate actions when credentials, permissions, routes or knowledge change.
6. Continue until no relevant attacker or defender action remains, the policy explicitly abandons the objective, or a configured guardrail is reached. Achieving a data objective records impact but does not immediately discard pending containment or investigation.
7. Derive results from the event history, retaining the termination reason, unresolved opportunities and conditional branches. Attach historical time labels only during projection.

Treat these as causal processing stages, not equal-duration turns. A response generated after a completed action cannot prevent that action. An unavailable or unconfirmed response cannot suppress its successor.

## 6 Versioned data contracts

Introduce estate schema version 4, a separate run-manifest version and an explicit engine version. IDs are stable strings. The structures below define required concepts; implementation may use plain JavaScript objects with runtime validation.

### 6.1 Estate and scenario

```js
const estate = {
  schemaVersion: 4,
  id: 'estate-...',
  archetypeId: 'public-web',
  estateSeed: 42,
  generationMode: 'exploratory', // or authored_walkthrough
  asOfDate: null,               // required for historical replay
  assets: [],
  routes: [],
  identityRelationships: [],
  weaknesses: [],
  credentials: [],
  datasets: [],
  sensors: [],
  enforcementPoints: [],
  patchRules: [],
  decoys: [],
  responseIntegrations: [],
  legitimateWorkflows: [],
  assumptions: []
};

const runConfig = {
  manifestVersion: 1,
  trialSeed: 17,
  initialAccess: [],
  initialKnowledge: [],
  objectives: [],
  limits: {
    maxActionAttempts: 100,
    maxRetriesPerAction: 2,
    maxInvestigationActions: 20,
    maxHumanAssists: 4,
    maxRecordedEvents: 10000,
    maxConditionalBranches: 16
  },
  interventionContracts: [],
  uncertaintyMode: 'report_conditional'
};
```

The shown limits are engineering guardrails, not historical measurements. Their values must appear in exports and remain equal across paired comparisons. Exhausting a guardrail produces an incomplete result, not defensive success.

### 6.2 Required entity fields and meaning

| Entity | Required fields and constraints |
| --- | --- |
| Asset | ID, role, product/version when applicable, trust zone, active interfaces, lifecycle metadata and layout hints. Layout layer is descriptive only. |
| Route | ID, source and target, protocol, accessible interface, policy predicates and traversed enforcement-point IDs. Network reachability alone grants no application privilege. |
| Identity relationship | Subject, issuer/tenant, target scope, allowed operation and delegation conditions. An identity trust edge is not automatically a network route. |
| Weakness | Kind, affected asset/interface, prerequisites, granted capability, affected-version/configuration predicates, source/provenance and reference identifiers. Non-CVE weaknesses are allowed. |
| Credential | Issuer, principal, audience, permitted operations, storage location, read prerequisites, expiry/revocation state and session-minting behavior. Ground-truth existence does not mean the attacker knows it. |
| Dataset | Owner asset, sensitivity, synthetic record units, whether it is real or decoy data, and allowed read/export operations. Public-facing sensitive data still counts as sensitive. |
| Sensor | Placement, observable action types, fields collected, attribution quality, collection availability and modeled loss conditions. Layer-level coverage can be a UI summary only. |
| Enforcement point | Route/service placement, inspected protocols and fields, rule IDs, enabled state, and any inspection prerequisites. |
| Decoy | Kind, placement, discoverability, attractiveness cues, trigger predicate, attribution fields and alert destination. A decoy may exist at any plausible layer. |
| Response integration | Supported actions, authorized scopes, session/token semantics, confirmation mechanism and availability conditions. |
| Assumption | ID, value or range, provenance type, source reference if available, applicable population/scenario, and review note. |

Use `provenanceType: historical_source | vendor_reference | expert_assumption | authored_fixture`. Reference membership is not proof that a deployment satisfies a weakness's prerequisites.

Validate the semantics as well as object references: a rule must request fields its enforcement point can inspect, an investigation must use an available integration, and a response must identify a supported scope. Any optional probability must be bounded to [0, 1], name the event and conditions it describes, and reference an assumption. Missing probability data must not be replaced with an undocumented actor multiplier or market-wide default. Deterministic fixtures can use explicit outcomes; exploratory configurations must declare whether uncertain behavior is sampled, branched or unresolved.

### 6.3 Run state and event history

Keep world state, attacker knowledge and defender knowledge separate. Maintain capabilities per host/principal/session, and record credential acquisition and session lineage explicitly. Shared attacker knowledge may coordinate branches, but sharing knowledge does not transfer privileges to an unrelated session.

```js
const event = {
  id: 'event-...',
  sequence: 12,
  causalParentIds: ['event-...'],
  branchId: 'branch-...',
  kind: 'action_result',
  actionId: 'action-...',
  actor: { principalId: 'principal-...', sessionId: 'session-...' },
  sourceId: 'asset-...',
  targetId: 'asset-...',
  routeId: 'route-...',
  outcome: 'succeeded',
  reasonCode: 'AUTHORIZED_SCOPED_READ',
  evidenceIds: [],
  controlId: null,
  stateChanges: [],
  objectiveChanges: [],
  assumptionIds: []
};
```

Define separate event kinds for observation, incident update, investigation, response proposal, response confirmation, decoy interaction and objective impact. Action outcomes include `succeeded`, `denied`, `failed`, `suppressed`, `not_attempted` and `budget_exhausted`. A containment event records an intervention; it does not retrospectively change a successful read to a blocked read.

Record proposed-but-suppressed actions as such. Do not increment attack-attempt counters for actions canceled before dispatch. Keep `controlBlocks`, `policyDenials`, `actionFailures` and `canceledActions` distinct.

### 6.4 Calibration and provenance register

Create `assets/calibration.json` as the versioned register for historical context and uncertain behavioral inputs. An entry must distinguish `observedStatistic` from `simulationAssumption`. The former records source URL, publication date, observation period/population, statistic type, value, unit and start/end milestones. The latter records the chosen value/distribution, applicable conditions, justification and uncertainty treatment. An observed mean must not silently become a median, and unreported percentiles must not be labeled source facts.

Each displayed number carries `source_fact`, `synthetic_assumption` or `simulated_outcome`, plus referenced entry/event IDs. A computed result inherits the assumptions that influenced it. Unknown values display as unknown; a missing observation is not evidence that an asset is healthy.

Primary-source checks for this revision establish two useful boundaries:

- CrowdStrike reports an **average** eCrime breakout of 84 minutes in 2022 and 62 minutes in 2023. Breakout is movement from an initially compromised host to another host; those figures do not establish time to a sensitive record or a p50/p90 distribution. [CrowdStrike 2024 report overview](https://www.crowdstrike.com/en-us/blog/crowdstrike-2024-global-threat-report/).
- GTIG describes one ARTEX-associated actor moving from a compromised account to deep access in about four hours typically, with one 15-minute case. It also describes burst/pause behavior and noisy trial-and-error, including possible subagent interference. These observations support varied behavior and coordination failures; they are not a universal ARTEX timing distribution or evidence of universal stealth. [GTIG ARTEX and Friends](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks).

Sources were checked on 16 November 2026. Do not derive a record-access duration from compromise-to-discovery dwell or disclosure-to-exploitation statistics without an explicitly justified model. Keep any resulting distribution labeled as an assumption. Hardware/model-speed calibration and response-latency races remain outside scope.

### 6.5 Explicit configuration failures

Return structured validation errors with entity ID, field path and reason. Missing required interfaces, invalid routes, unsupported operations, absent mandatory policy definitions and malformed calibration entries prevent that run from starting. Remove implicit HTTPS defaults and sentinel ordering for undeclared assets; candidate ordering must follow the explicit policy with stable tie handling.

Distinguish intentional absence from missing configuration. A CVE need not have a working detection or virtual patch: declare coverage as `configured`, `not_deployed`, `not_applicable` or `unknown`. A configured rule missing its definition is an error. Unknown coverage must remain unknown or conditional if it affects the result, rather than silently becoming an ineffective control.

If a selected scenario requires the reference catalog or calibration file and loading fails, show the error and prevent starting that scenario. An optional reference-only catalog failure may leave an explicitly labeled standalone scenario available, but must not silently run a different scenario. Add a retry action and retain the last valid manifest without claiming the failed update loaded.

## 7 Infrastructure generation and causal paths

### 7.1 Archetypes

Start with four coherent archetypes rather than expanding the product pool first:

| Archetype | Required relationships | Important defensive variations |
| --- | --- | --- |
| Enterprise identity and endpoints | Remote access, user/service identities, workstation/server access and internal data | Identity restrictions, endpoint telemetry, management isolation |
| Public web and internal data | Public application, middleware, application identity and datastore permissions | WAF placement, exposed origin, application telemetry, least privilege |
| Cloud and SaaS | Tenant identities, role grants, API permissions and cloud datasets | Audit coverage, session controls, credential scope, direct data access |
| CI/CD and operational secrets | Repository, runner, service identity, artifact/configuration store and deployment target | Secret handling, runner isolation, token scope, deployment authorization |

Each template must specify ownership, routes and trust assumptions. Permit same-layer and cross-layer edges, direct cloud-data access, and return paths where justified. A visited-state guard must prevent cycles from running forever. Reconsider an action when a relevant capability, credential or control state changes; a one-time visited-edge flag is insufficient.

Make the first archetype operational rather than decorative: supply identity/AD, endpoints and their sensors, remote administration, file-share access and appropriate data permissions. Collaboration/messaging services and hypervisors can be optional reviewed extensions; OT/hybrid remains a separate later archetype unless it has equivalent causal modeling. In the reviewed implementation, `REVIEWED_EXAMPLES` supports the ten edge-appliance families plus `cust-api` and `app-engine`; many other displayed CVE mappings do not become executable CVE findings through `addCveFindingForAsset`. Audit every advertised surface and add a coverage manifest identifying executable actions versus contextual labels. Do not advertise an older profile's SMB or endpoint capability when its selected estate has no modeled opportunity for it.

Choose routes from archetype service and identity requirements. Screen coordinates may lay out a route but must not decide which service a credential or application can reach. Provide at least one conventional and one agentic policy fixture over each shared archetype, without reserving mutually exclusive routes by actor name.

### 7.2 Replace exercise shortcuts

Remove `kind: 'exercise'` authorization branches from both action and defense evaluation. Replace `seedExercise()` with `instantiateScenario(template, estate)` for authored walkthroughs. The function adds explicit modeled conditions and validates the intended route through the ordinary evaluator.

A walkthrough may intentionally contain a viable baseline path. Mark it `authored_walkthrough` and identify its conditions in the UI. A walkthrough with an unsatisfied required condition must fail validation; do not silently grant an exercise session. Exploratory generation must not resample estates until a desired success rate is reached or add vulnerabilities to every object merely to preserve a path.

Assets without reviewed CVEs remain valid assets. Access may depend on scoped credentials, misconfiguration, public information or no available path. Do not manufacture a CVE to fill a route. Distinguish `app_exec`, `file_read`, `authenticated_session`, `data_read` and administrative permissions; none is interchangeable without an explicit grant.

### 7.3 Catalog and lifecycle handling

Add `referenceRole: context_only | modeled_weakness | modeled_chain` to catalog entries. Only modeled weaknesses/chains require exact compatible product, version, interface and prerequisite mappings. Context-only entries must not attach the reference CVE as an active node vulnerability. A consumer-device reference may remain contextual or belong to a suitable branch-office archetype; no blanket deletion by vendor class is required.

Remove the DOM's position-based `Decommissioned` and `P.o.C` suffixes. If lifecycle is displayed, read it from the estate. A decommissioning label does not disconnect an asset; disabled interfaces and removed routes do. A proof-of-concept deployment can be monitored or unmonitored according to its sensors.

The Git-to-IdP illustration must either become an explicit, prerequisite-checked chain or remain clearly labeled contextual artwork excluded from run outcomes. Never report IdP administration solely because a log read occurred.

## 8 Attacker behavior and exploration

### 8.1 Separate behavior from historical identity

Use two editable behavior presets: `operator_with_tools` and `agentic_orchestration`. Existing actor names may remain as historically sourced technique metadata or display labels. They must not directly supply detection availability, canary placement, stealth multipliers or success flags. SOC tickets must describe observed behavior, not insert a famous tool or actor solely because a preset was selected.

Profile fields should include supported action families, available tool handlers, concurrent branch limit, discovery policy, adaptation repertoire, evidence-verification policy, human-assistance policy and retry/effort costs. Explicit tool outputs supply new opportunities. Neither profile receives the full graph automatically.

Operator-led attackers can use scripts, parallel tools, credential chains and analyst judgment. Agentic orchestration can automate context-dependent continuation and coordinate branches, but can also misinterpret evidence, repeat ineffective actions or request assistance. Unsupported parsing or uncertain inference can lead to a verified failure or a hypothesis requiring a check. Do not turn an unverified belief into a world-state grant.

`historical_replay` restricts available technologies and knowledge to an `asOfDate`. `capability_comparison` puts both behavior profiles on the same selected estate and labels a pre-2023-style operator on modern infrastructure as a counterfactual. Exploit age and attacker autonomy are separate dimensions.

### 8.2 Frontier execution and fair budgets

Replace the adjacent-layer traversal with a frontier of known candidate actions. Select actions according to the profile and observations. Every attempted action consumes the same defined attempt budget; tool-specific costs, if used, must be explicit and applied identically to both profiles.

Concurrency means multiple active branches and independently pending actions. It does not multiply the total attempt allowance. Do not terminate after a fixed number of rounds to manufacture an agentic advantage. Record branch breadth, duplicated work, abandoned branches, assistance requests and validated discoveries as distinct metrics.

Actions selected together read a common pre-action state. A dependent action cannot use a credential that another action in the same batch has not yet produced. Merge independent changes; explicitly resolve conflicting changes. When outcome depends on an unspecified ordering, use the conditional-outcome policy in Section 12 rather than sorting by asset ID to choose a winner.

### 8.3 Adaptation and observability

Adaptation selects another available action, route or abstract request variant after a meaningful observation. Success is evaluated through the same prerequisites and controls as the original action. A blocked request supplies only the information represented by its response; it does not reveal the complete rule configuration.

Do not implement `adaptiveWafEvasion: true` as a bypass. A weak matcher may miss an explicitly modeled variant, and either attacker may discover that variant. Another matcher may cover all variants available to the attacker. The simulator need not carry working exploit payloads; abstract action/variant identifiers and rule predicates are sufficient.

Noise and detection footprint derive from actual behavior: request counts, operations, process events, identity use, privilege changes and data actions. A small request count does not suppress identity or data-audit events. Broad scanning is not necessarily malicious in a legitimate workflow.

## 9 Virtual patching

A patch may prevent an action only when all required conditions are true:

1. The action traverses a referenced enforcement point or invokes a protected service hook.
2. That point is enabled and can inspect the relevant protocol and fields.
3. A deployed rule covers the operation, interface and modeled action variant.
4. The rule's enforcement action is supported and applies to this request.

Return a structured result with `covered`, `matched`, `enforced`, `ruleId`, `enforcementPointId` and a reason code. Suggested reasons include `OUTSIDE_CONTROL_PATH`, `UNSUPPORTED_PROTOCOL`, `INSPECTION_UNAVAILABLE`, `RULE_NOT_MATCHED`, `MONITOR_ONLY` and `RULE_ENFORCED`.

Separate vulnerability-specific rules from access restrictions. A rule can restrict anonymous access or a credential-bearing operation when explicitly configured; valid credentials do not automatically bypass every application-layer rule. Conversely, a CVE identifier alone cannot cause a block without matching traffic and placement.

The first release uses predeployed rules. Dynamically generated SOC patches are optional later work and must be recorded as proposed, validated and activated controls. No retroactive blocking is allowed. Add legitimate requests to measure false blocks and affected workflows. One blocked malicious request does not imply the protected service is unusable or all alternate paths are closed.

## 10 Canaries and honeytokens

Instantiate decoys before the comparison and preserve their candidate placement across attacker selection. An enabled defense overlay specifies which decoys are deployed and instrumented; changing this overlay must not regenerate unrelated estate assets or secrets.

Support at least decoy services/data and honeytoken credentials. Define trigger predicates such as decoy-file read, request to a decoy service or attempted use of a honeytoken at an instrumented verifier. Some triggers occur on denied requests. Requiring a successful eligible compromise for every canary trigger would miss these cases.

The attacker discovers and selects decoys through the same observation system as real objects. The policy cannot inspect `isDecoy`. The operator's diagram may reveal decoys, with an optional attacker-knowledge view that hides them. A honeytoken must not silently grant production access; a real credential intentionally used as a monitored lure needs an explicit, separately labeled scenario.

Track interactions and alert deduplication by decoy and relevant identity, not one global `canaryTouched` flag. Record trigger event, available attribution, alert delivery and associated incident. An unconnected or unobserved lure produces no magical signal. Legitimate scanners or administrators can interact with a decoy where the scenario allows it; include that possibility in evaluation.

Canary-only mode reports detection and investigative value. It does not revoke access. SOC-plus-canary passes the same alert to the same response policy used in SOC-only mode. High-confidence suspicious activity is not necessarily high-confidence session identity or sufficient authority to revoke a token.

## 11 Agentic SOC and response mechanics

### 11.1 Observations and investigations

Sensors emit only events they can observe. Represent availability, missing fields, collection failures and correlation identifiers explicitly. Include events from relevant identity, application, host and data sources instead of a universal boundary signal. Static `KEV_MITIGATION_RULES[cve].ml` entries can become documented detection hypotheses; they must not directly grant containment.

Use incident states such as `untriaged`, `investigating`, `insufficient_evidence`, `action_proposed`, `awaiting_authority`, `enforcement_failed`, `enforcement_confirmed` and `closed`. Store rationale and evidence references on every transition.

The agentic policy can choose among bounded investigation actions: inspect identity context, correlate observed activity, verify a suspected exposure or inspect a resource's access policy. Each action requires an available integration and can return useful evidence, uncertainty or failure. A fixed-playbook policy should be available as an optional comparator so the value of investigation and action selection is distinguishable from generic automation.

An optional human-led SOC comparator uses the same sensors, investigation permissions and response integrations. Differences must come from an explicit decision/assistance policy, not a rule that human SOC has fewer sensors or cannot correlate low-volume activity. If comparing different deployments is useful, present it as a separate posture comparison. Include an identical-policy control case that produces identical outcomes regardless of the human/agentic display label.

Cross-boundary activity is a feature, not a verdict. A detection hypothesis must explain which observed behavior conflicts with expected roles, access patterns or known legitimate workflows. Include benign and ambiguous cases, wrong identity attribution and erroneous containment. Ground-truth maliciousness is for evaluation only.

### 11.2 Response authority and scope

Supported first-release actions: revoke a credential, invalidate a session where supported, disable an account within an authorized scope, isolate a modeled host, or close a specific public exposure. Each action requires matching integration permissions and an explicit state-change contract.

Track credential issuance and session lineage. Revoking a token does not necessarily invalidate already minted sessions; account disabling does not necessarily terminate every active session. The integration contract specifies the effect. Host isolation affects routes that depend on that host. Closing one public bucket does not revoke unrelated identities.

A response executor returns `confirmed`, `failed`, `unsupported`, `approval_required` or `scope_unresolved`, with evidence. Only confirmed state changes can suppress future actions. Partial enforcement remains partial. Duplicate responses should be idempotent, with deduplication keys and a visible audit record.

### 11.3 Operational tradeoffs

Record legitimate workflows disrupted, legitimate identities affected, investigation work and unresolved incidents. Do not add arbitrary dollar losses or universal false-positive probabilities. Use authored benign fixtures initially; add weighted workloads only with an explicit assumption manifest.

## 12 Causal ordering without a model-speed race

The engine must retain causal order: an access attempt can produce an observation; an investigation can use that observation; a confirmed response can change later permissions. This does not require a second-by-second offensive/defensive speed model.

Distinguish preventive controls from reactive interventions. A matching inline patch is evaluated within the attempted operation, before its protected effect. A reactive control affects a later action only if the scenario establishes that enforcement is effective at that authorization or access decision.

Use explicit intervention contracts for outcome-sensitive reactive cases:

| Contract | Meaning |
| --- | --- |
| `confirmed_before_action` | A named response is effective before a named dependent action or authorization check. Requires a valid response and a declared scenario condition. |
| `confirmed_after_action` | A named action has completed before the response; completed impact remains in the result. |
| `not_confirmed` | Response fails, lacks authority or is unavailable; no state change is credited. |
| `ordering_unspecified` | Both causal continuations may be feasible; report conditional outcomes rather than selecting a winner. |

These conditions are part of the comparison manifest and held constant across profiles unless a modeled action changes their prerequisites. The UI must identify a favorable intervention condition when prevention depends on it. Do not secretly implement “SOC always acts before the next attacker turn.”

For unspecified order, evaluate the feasible before/after continuations within a bounded branch limit. Report common conclusions and differing impact, such as “session can be revoked; sensitive read depends on whether revocation is effective at the next access check.” If branching reaches its limit, mark the unresolved portion incomplete. Never average conditional outcomes into a protection probability without explicit scenario weights.

This mechanism evaluates defensive capability and scope while leaving model-dependent execution speed outside the comparison. Timestamp labels, playback speed and rendering order are projections of the causal trace and must not choose an outcome.

## 13 Comparison, reproducibility and metrics

### 13.1 Independent control configurations

Represent defenses as independent switches:

```js
const defenseConfig = {
  virtualPatching: true,
  canaries: true,
  responsePolicy: 'agentic' // observe_only | playbook | human_led | agentic
};
```

Observation-only retains normal sensors but permits no active SOC response. Baseline retains inherent network policy, authentication and authorization; it does not mean every security constraint is disabled. Sensors and response privileges are fixed estate properties, while the selected defense configuration determines which optional controls/policy are active.

Provide presets for baseline, patch, canary only, SOC, SOC plus canary, and all three. An advanced comparison exposes all eight on/off combinations of patch, canary and the selected active SOC policy. Keep policy selection separate. An “all three” cell must not be mislabeled SOC plus canary.

Compare incremental effects against the corresponding control-disabled cell. Disabling a canary removes its deployed lure and signal according to the overlay contract; it may legitimately change attacker exploration. Keep unrelated topology and random assumptions unchanged. Do not require identical final attack paths after defenses alter observations.

### 13.2 Deterministic randomness

Use independent namespaces for estate generation, attacker decisions, observations, response failures and presentation. Derive a draw from stable semantic keys, for example `hash(trialSeed, namespace, entityId, actionVariantId, attemptOrdinal)`. Attempt ordinals are local to that action/branch lineage, not global event counts.

Do not key shared environment draws on the defense label, actor display name or the complete mutable state hash. Adding a sensor or rendering a new node must not reroll unrelated vulnerabilities or credential validity. Repeated attempts need distinct, recorded keys so retries are neither accidental rerolls nor permanently stuck on one random value.

Export the full estate, profiles, control overlays, initial state, objective definitions, budgets, intervention contracts, seeds, engine version, assumption provenance and event trace. A seed alone is not a durable replay format across engine versions.

### 13.3 Outcomes

Report independently:

- Objective state: not attempted, denied, partially achieved, achieved, conditional or incomplete.
- Access: reached assets, privileges and independent sessions, with lineage.
- Impact: actual sensitive datasets read and simulated units exported; exclude decoy data from real-data impact.
- Detection: relevant observations, incidents, decoy alerts, attribution confidence and missed activity.
- Response: proposed, authorized, confirmed, failed and partial interventions, with affected scope.
- Costs: action attempts, retries, assistance, investigations, duplicate work and legitimate-workflow disruption.

Prevented impact requires a viable corresponding baseline and an attributable intervention. If baseline has no viable path, report “no viable modeled path” rather than a defense success. Where a trace ends because the action policy or budget stops exploring, report that limitation; do not equate unexamined opportunities with impossible paths.

A sensitive public dataset counts as impact even in Layer 0. A public brochure does not become sensitive because it is in Layer 3. Reading a decoy may constitute detection but not loss of the actual objective. Sensitive read and export are separate modeled operations.

Aggregate only comparable, explicitly selected scenario populations. Show counts and denominators, unresolved runs and weighting assumptions. Seed sweeps test internal behavior and sensitivity; they do not establish field effectiveness percentages.

## 14 UI and explanation requirements

Preserve New Infra, Replay and Results. Add an archetype/scenario selector, defense presets, an advanced independent-control panel and a comparison results view. The active view and every comparison cell must use the same engine and immutable manifest.

Display the estate ID/seed, generation mode, attacker behavior preset, active controls and historical context. New Infra creates a new estate. Changing attacker, defense, layout, window size or playback position must not regenerate it. Give users an explicit new trial action if they want a different realization of uncertain decisions on the same estate.

For each node, route and event, expose a “Why” panel containing prerequisites, known observations, relevant rule/sensor, response scope, reason code and assumptions. Distinguish modeled compromise, available opportunity and contextual artwork. De-emphasized or hidden nodes still contribute to the complete result.

Use separate visual states for no access, access established, patch prevention, policy denial, decoy alert, confirmed containment, impact, conditional outcome and incomplete exploration. Do not apply the `contained` class merely because no sensitive read occurred. A contained session and an already compromised dataset may coexist visually.

Render canary placement for the operator without exposing that flag to attacker logic. Group events into tickets without discarding evidence. Titles and severities come from the event type and impact model, not the actor name. Show no invented follow-on events after a blocked dependency.

Historical elapsed time is a labeled contextual display. Animation speed is a user preference with reduced-motion support. No playback setting can influence attempts, telemetry, response decisions or outcomes.

## 15 Migration and implementation work packages

### WP1 Schema and integrity

Implement version-4 validation, objective classification, explicit scope and budget contracts, configuration-error handling and the calibration/provenance register. Remove defense-specific data caps from `simulateEstate`; keep rendering caps only in the view. Add reason-coded suppression and incomplete outcomes. Add immutable-input checks.

**Exit gate:** baseline and observation-only SOC have equivalent reachable state when no control acts; layout limits cannot change results; sensitive data is classified by dataset, not layer.

### WP2 Estate and action model

Introduce archetypes, typed routes and identity relationships. Replace exercise findings with authored conditions. Expand validation to include references, supported capability/operation types, credential audiences, route/interface compatibility, dataset objectives and control placement. Refactor the frontier to permit legitimate non-adjacent paths and capability-dependent revisits.

**Exit gate:** every successful fixture action has a prerequisite proof; removing any essential condition removes the dependent result. No guaranteed exploratory breach rate remains.

### WP3 Attacker and observations

Implement knowledge-limited action selection, fallible adaptation, concurrency with shared total budgets, sensor placement and explicit decoys. Remove actor-owned `boundarySignal`, `canary` and any global stealth multiplier. Split old mitigation lookups into patch definitions and observation hypotheses.

**Exit gate:** actor renaming does not change outcomes; both profiles can succeed and fail at adaptation; decoy alerts require matching interactions; unsupported observations never appear.

### WP4 SOC and control execution

Implement investigation, authority checks, scoped integrations, session lineage, response confirmation and the intervention contracts. Route ordinary and canary evidence through the same SOC policy. Add benign workload fixtures and disruption metrics.

**Exit gate:** no containment from an alert alone; failed enforcement changes no access state; unrelated sessions continue unless the confirmed response explicitly covers them; unspecified ordering remains conditional.

### WP5 Unified comparison and presentation

Adapt `simulateWireRun` temporarily to the new facade and migrate `evaluateComparisonRun`/`evaluateComparisonMatrix` fixtures onto it. Remove the old evaluator only after useful no-signal, decoy, scope and denied-access cases have equivalent coverage. Do not preserve obsolete timing-race assertions as acceptance requirements.

Update `wire.html` to consume projected events and the new result model. Add export/import and comparison controls. Correct catalog reference roles and lifecycle labels.

**Exit gate:** graph, tickets and metrics agree for every cell; replay and mid-playback switching remain stable; no duplicate engine decides different results for the same manifest.

### WP6 Scenario review and documentation

Publish the minimum fixture suite below, archetype assumptions and instructions for adding a scenario. Update README and wire logic documentation to describe the implemented model and distinguish historical context from modeled outcomes. Rewrite tests that assert a desired winner or aggregate breach percentage.

**Exit gate:** all invariants and fixtures pass, scenario assumptions are visible, and reviewers can explain each outcome from its trace without relying on actor stereotypes or clock races.

### Snapshot compatibility

Do not silently regenerate a saved estate when importing an older snapshot. Preserve the original file. Import version-3 snapshots only through an explicit converter that reports unsupported exercise findings and missing sensor/control/objective information. It may produce an incomplete draft scenario requiring supplied assumptions; it must not claim equivalent replay. Otherwise return an actionable incompatibility message and offer separately to generate a new estate.

## 16 Verification and minimum fixture suite

Tests verify model consistency and the stated scenario conditions. They are not live effectiveness tests. Keep the existing Node regression entry point and add focused test files as needed. Every fixture supplies a full manifest and checks causal reason codes, affected scopes and objective state.

| ID | Fixture | Required result |
| --- | --- | --- |
| F01 | Authored path loses its required source capability | Dependent access fails through the common evaluator; no exercise fallback. |
| F02 | Credential has wrong audience, missing permission or revoked state | Authentication/operation is denied; the reason identifies the failed condition. |
| F03 | Same request uses covered path and uncovered alternate path | Patch applies only at the enforcement point actually traversed. |
| F04 | Two profiles choose the same abstract variant against the same rule | Rule outcome is identical; changing actor label alone has no effect. |
| F05 | Both profiles have a modeled alternative variant, but one fails to discover it | Difference is explained by observations and decisions, not a profile-specific bypass. |
| F06 | HTTP WAF faces non-HTTP traffic | It claims no block; unsupported inspection is recorded accurately. |
| F07 | Explicit access restriction covers a credential-bearing request | Apply that policy instead of assuming all valid-credential actions bypass controls. |
| F08 | Decoy exists but is undiscovered or untouched | No canary alert. |
| F09 | Honeytoken use is denied by an instrumented verifier | Alert may still fire if its trigger is attempted use; no production access is granted. |
| F10 | Two distinct decoys are touched | Both interactions exist; deduplication does not suppress the second decoy. |
| F11 | Canary-only mode alerts while a real path remains viable | Detection is reported; no automatic revocation or prevention is credited. |
| F12 | Canary identifies suspicious activity but not a revocable identity | Incident remains actionable/uncertain; no unsupported session containment. |
| F13 | SOC response is unauthorized, unavailable or fails confirmation | No effective state change; failures remain visible. |
| F14 | One session is revoked while another is independent | Only the integration's explicit scope is affected. |
| F15 | Token revoked after a session was minted | Existing session behavior follows the integration contract, not a universal assumption. |
| F16 | Benign service workflow crosses several trust boundaries | Boundary count alone does not convict it; any false intervention is measured. |
| F17 | Sensitive public dataset, ordinary internal content and decoy archive | Count sensitive impact by classification; do not equate layer or decoy access with breach. |
| F18 | Control produces no signals or enforcement | Same budgets and policy yield the baseline state; no artificial data-layer cap benefit. |
| F19 | Both attackers have equal total attempts but different concurrent branches | No hidden multiplication by round count; dependent actions wait for their prerequisites. |
| F20 | New evidence enables a previously ineligible route, including a graph cycle | Revisit the relevant state safely; terminate under explicit guards. |
| F21 | Response ordering is unspecified and changes the objective result | Return conditional outcomes with the controlling assumption, not a fabricated winner. |
| F22 | Response confirmed after sensitive read | Preserve impact and report later containment separately. |
| F23 | No viable baseline path | Do not attribute safety to an optional defense. |
| F24 | Attempt/event/branch guardrail exhausted | Mark unexamined outcomes incomplete and preserve known impact. |
| F25 | Switch control overlay, actor label or presentation settings | Unrelated estate draws stay fixed; labels and presentation alone change no causal state. |
| F26 | Export and reimport a supported manifest | Identical deterministic trace and objective results. |
| F27 | Import a legacy snapshot | No silent regeneration or false claim of equivalent replay. |
| F28 | A legitimate request is incorrectly blocked | Record false block and affected workflow alongside any protective benefit. |
| F29 | Catalog entry is context-only or lifecycle label changes | No inferred exploit, connectivity change or monitoring loss. |
| F30 | Combined controls block an upstream dependency | Downstream actions are canceled/not attempted, not shown as successful or extra attack attempts. |
| F31 | Human-led and agentic SOC labels use identical policies and deployment | Identical decisions and outcomes; labels confer no detection or authority advantage. |
| F32 | Required interface/rule/calibration data or selected catalog fails to load | Explicit validation/loading failure; no silent substitution or healthy/default-control result. |
| F33 | A calibration entry provides only an observed mean | It cannot present p50, p90 or a fitted distribution as source facts without separate evidence. |
| F34 | Fixed action traverses an additional correctly configured enforcement point | Validate local matching/enforcement semantics; do not impose a universal aggregate winner on adaptive runs. |
| F35 | A profile advertises an action family with no usable estate surface | The coverage manifest exposes the gap; display-only CVEs do not become implicit exploitable findings. |

Add property checks across bounded seed sets for input immutability, unique IDs, valid references, deterministic replay, prerequisite closure, evidence visibility and equal comparison budgets. Keep deterministic scenario assertions as well as optional multi-trial sensitivity runs; sampling does not replace causal unit tests. Report differences and unresolved cases without forcing all aggregate effects to be monotonic. Do not assert that ARTEX must win more often, canaries must always stop it or a particular percentage of estates must breach.

Browser acceptance must cover defense combinations, attacker changes during playback, Replay, Results, resize, reduced motion, imported manifests and incomplete/conditional results at desktop and narrow widths. Check graph/ticket/result agreement and console errors. Changing viewport or animation settings must leave the manifest and causal trace unchanged.

## 17 Evidence and release criteria

The earlier implementation review found identical baseline action sequences for LockBit and ARTEX across 200 seeds after removing timestamps; exercise access survived unavailable source-capability requirements in 163 estates; and seed 42 reached two data assets in baseline versus one under SOC with no control events. These observations motivate R01, R04 and R08. They are reproducible with [review-comparison.cjs](../scripts/review-comparison.cjs) against the reviewed revision and recorded in [comparison-review-evidence.json](comparison-review-evidence.json). Keep that evidence versioned; update or retire the legacy probe when the public API changes rather than treating its old counts as new targets.

The release is acceptable when:

1. All R01–R14 invariants and F01–F35 fixtures pass through the same engine used by the UI.
2. Every successful hop and effective intervention has an inspectable causal explanation.
3. Each attacker profile has plausible success and failure cases under explicit conditions.
4. Patch effectiveness follows path and rule coverage; canary value follows interactions and attribution; SOC value follows evidence, investigation, authority and confirmed scope.
5. Comparisons preserve the underlying estate and budgets, disclose deployment differences and unresolved conditions, and do not infer broad effectiveness from a seeded demonstration.
6. Historical elapsed-time context can change independently without changing who succeeds.
7. A reader can reproduce a result from its exported manifest and identify the assumptions whose alteration would change it.

The intended outcome is a credible, inspectable simulation of different attack and defense mechanisms. Its value comes from showing which conditions matter and what each mechanism can actually change.
