# ARTEX comparison sandbox realism review

15 November 2026

Reviewed revision: `286cf02952b87b0525ee4c9cc718543f54a759cd` on `main`.

## Assessment

**The sandbox is a useful illustration of attack progression and defense timing, but only partly achieves the objective of a realistic simulation comparing older and agentic attackers across plausible infrastructure.** Its strongest features are repeatable estates, explicit access prerequisites in the general evaluator, scoped credentials, and distinctions between prevention, telemetry and containment. Its principal weakness is that several important outcomes are consequences of scenario construction rather than consequences of the modeled environment and attacker behavior.

Historical attack durations are an appropriate input to this simulation. Realism does not require measuring local Docker request latency, executing real exploits, or putting an actual LLM in either attacker or defender. It requires a coherent account of what consumes the time, what each participant can observe and do, and which conditions cause a defense to succeed or fail.

The highest-value change is to retain the historical clock while making the **last part of the attack, detection opportunity, and enforcement time independently configurable and causally connected to events**. The simulator should be able to explain why a fast attacker sometimes loses to ordinary SOC response, why an older attacker sometimes wins, and why a canary sometimes helps and sometimes does not, without assigning those outcomes directly to attacker names.

### Fit against the objectives

| Objective | Assessment | What is needed |
| --- | --- | --- |
| Plausible overall attack duration | Partial | Traceable historical inputs with matching start and end milestones; credible variation within each profile. |
| Older versus agentic attack behavior | Weak | Different planning, discovery, concurrency, adaptation and failure behavior; the active model mainly changes timestamps and signal settings. |
| Plausible infrastructure | Partial | Coherent deployment archetypes and causal access paths; product variety alone does not establish realism. |
| Virtual patching | Partial | Coverage tied to an enforcement point, traffic path and action, including operational tradeoffs. |
| Canaries | Weak | Explicit decoys, discovery and interaction conditions, alert delivery and identity attribution. |
| Agentic SOC | Weak | Modeled investigation, decision, scope and enforcement uncertainty instead of a universal response timer. |
| Fair comparison of defenses | Partial | Equal exploration budgets, independent defense switches and a consistent outcome definition. |

## What the implementation already gets right

The same generated estate is reused when the attacker or defense selection changes. The seeded engine makes those comparisons repeatable. The ordinary action evaluator checks direction, source capability, interface, product, assumed version and configuration before granting access. Credential checks cover scope, audience, expiry, revocation and MFA. These are useful foundations for a realistic simulation and should be preserved.

The active SOC modes also separate signal, decision and enforcement timestamps, retain session-related scope, and can show containment after a data read. The existing comparison fixtures cover no signal, late or untouched decoys, timing ties and unrelated identities. The README correctly describes the results as illustrative. The problem is not lack of effort or lack of disclaimers: it is that the active wire model does not consistently apply its stronger concepts.

Evidence: [action evaluator](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L590), [credential checks](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L814), [comparison fixtures](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L2573).

## Priority findings and fixes

Priority 1 means the issue can materially determine or misattribute a comparison result. Priority 2 means the issue limits realism or the conclusions that can reasonably be drawn.

### 1 Historical total duration does not determine the detection race

**Priority 1.** `wireTiming()` draws an ARTEX-like time to record read between 45 and 75 minutes, then places the boundary event exactly 50 seconds before the read and the internal-service event exactly 35 seconds before it. SOC enforcement always takes 60 seconds. Consequently, on a signaled path that reaches the record, ordinary SOC is ten seconds late by construction. Older attackers use different stage proportions, leaving a much larger response window.

The realism problem is the fixed distribution of time within the attack, not the use of historical total durations. Historical time to initial lateral movement, time to data access and time to detection describe different intervals. An overall duration does not establish that every agentic attacker completes the final stages in a 50-second burst.

**Suggested fix.** Keep the historical duration ranges as scenario inputs, with a source and an explicit start/end definition. Model discovery, access acquisition, lateral movement, data discovery and record access as separate steps. Give each step a plausible duration range and dependencies. Permit bursts, pauses, retries and waiting periods. Where only total duration is known, expose stage allocations as uncertain assumptions and run several plausible allocations. Vary response latency independently. Define and display the interval from the first actionable signal to impact; this is what a response must beat.

**Acceptance check.** With the same overall attack duration, changing only signal placement or the final-stage duration must be able to change the SOC outcome. A faster total attack must not automatically imply a shorter interval from detection to impact.

Evidence: [timing and attacker settings](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L2522). For the historical distinction, CrowdStrike defines breakout as movement from an initially compromised host to another host, reporting an 84-minute average for 2022; this does not directly calibrate time to protected-record access. [CrowdStrike 2023 report](https://www.crowdstrike.com/wp-content/uploads/2023/02/2023-Global-Threat-Report-Executive-Summary.pdf).

### 2 Attacker profiles combine speed with predetermined visibility

**Priority 1.** `WIRE_ATTACKERS` assigns LockBit and Hive boundary signals on all applicable paths, BlackCat and REvil no boundary signals, and Conti only the first scope. It separately assigns early, late or untouched canaries. ARTEX receives all boundary signals and an early canary. These choices can dominate the result even when the infrastructure is identical.

In the active model, both profiles use the same action evaluator and ordering. ARTEX's three probe lanes are primarily a presentation setting: the baseline action sequences were identical to LockBit's in all 200 reviewed seeds after removing timestamps. There is no corresponding active scheduling model in which three workers consume time, encounter failures, share findings or change the plan.

**Suggested fix.** Separate attacker capability from defender visibility. Describe attackers using automation, concurrency, available techniques, discovery ability, retry cost, stealth preferences and human handoff delay. Generate telemetry from the actions and installed sensors. Named groups can supply documented behavior presets, but should not directly switch monitoring off. Include conventional scripted automation in the older profile; distinguish agentic planning from automation itself.

Keep exploit age and attacker autonomy as separate dimensions. A current agent can exploit an old weakness. A historical replay, however, must restrict knowledge, infrastructure and vulnerabilities to the chosen date. Label a pre-2023-style operator on a modern estate as a counterfactual comparison, not a reconstruction of a historical incident.

**Acceptance check.** Hold pace constant and vary planning or concurrency to show their independent effects. Hold actions and sensors constant and verify that merely changing the actor's name does not change detection.

Evidence: [profile settings and lane count](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L2522), [probe animation](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/wire.html#L847). Anthropic's campaign account supports modeling orchestration and human decision points, but also reports incorrect credentials and mistaken success claims. Those are useful failure modes to represent, rather than assuming uniformly successful autonomous reasoning. [Anthropic campaign report](https://www.anthropic.com/news/disrupting-AI-espionage).

### 3 Authored exercise paths override the infrastructure constraints

**Priority 1.** The active UI enables `seedExercise`. The generator chooses a route and usually adds four successful exercise stages. `evaluateDistinctActions()` accepts those stages before ordinary protocol, capability, credential and vulnerability checks. Subsequent stages need an `exercise_session` and the matching route, rather than the access actually required by that infrastructure. Exercise steps also take precedence over other actions on that transition.

Authored paths are entirely appropriate for a simulation. The issue is that this path can remain successful when the modeled infrastructure says it should be impossible. The resulting estate is visually varied without an equally varied causal explanation for compromise.

**Suggested fix.** Retain authored scenarios, but express each step as a real modeled condition: an exposed diagnostic record, a credential with defined privileges, an exploitable interface or an explicit authorization weakness. Feed these through the common evaluator. Keep a separate illustrative walkthrough mode if guaranteed progression is useful. For exploratory scenarios, avoid inserting a successful route simply to make the demonstration interesting; instead include deliberately selected vulnerable and well-defended estates with visible assumptions.

**Acceptance check.** Removing a required privilege, closing the relevant route or revoking the credential must stop the dependent step, including an authored exercise step. Preserve alternative actions on the same transition.

Evidence: [early exercise return](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L590), [exercise construction](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L1264), [exercise insertion and ordering](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L1841).

### 4 Canary benefit is largely supplied as an assumption

**Priority 1.** In active `soc-canary` mode, an early canary signal is scheduled after the first successful external action other than diagnostics. A late signal is scheduled after a data read. This does not require reaching an explicit decoy. The separate `canaryAsset` selection applies to the older `combined` mode, so active runs can emit canary signals while returning `canaryAssetId: null`.

An early signal is a plausible scenario, but it needs a plausible cause: the attacker encountered a decoy and did something observable with it. Otherwise the comparison mainly asks whether giving SOC an earlier alert helps.

**Suggested fix.** Represent decoy files, accounts, services or tokens as objects in the estate. Specify where they are visible, what makes them attractive, what interaction triggers them and which identity can be attributed. Let the attacker select or ignore them using its discovery and target-selection policy. Model delivery delay and uncertain attribution separately. Keep “early”, “late” and “untouched” as explainable scenario outcomes or explicit walkthrough presets.

**Acceptance check.** Removing the decoy must remove its signal. An undiscovered or untouched decoy must remain silent. A triggered decoy must not automatically contain the attacker; it supplies evidence to a response policy. Another session may continue if the attribution or response scope is narrow.

Evidence: [canary selection](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L969), [telemetry generation](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L1015).

### 5 Agentic SOC is represented as a fixed response policy

**Priority 1.** The active wire model turns qualifying telemetry into a decision after 15 seconds and enforcement after 60 seconds. It does not model investigation, evidence quality, queueing, approval requirements, response selection, failed control actions or confirmation. In timed response modes, the per-action defense evaluator is called in baseline mode; the boundary signal and timer supply the response behavior instead.

This is a reasonable abstraction of one automated playbook. It is too narrow to answer whether an agentic SOC helps across different situations. A realistic simulation does not need a live SOC agent, but it should represent the behavior that makes the SOC agentic.

**Suggested fix.** Use a small state model: telemetry arrives, evidence is correlated, investigation resolves or fails, a response is selected, permissions or approvals are checked, enforcement executes, and its effect is confirmed. Parameterize these stages by telemetry quality, integration coverage, workload and action type. Include a fixed-playbook comparator alongside the agentic policy so any claimed benefit can be attributed to investigation or response selection. Model wrong decisions and operational disruption as well as speed.

**Acceptance check.** Missing telemetry, ambiguous identity, unavailable response permissions and failed execution must produce different outcomes. A failed control call must not be counted as effective containment. Better reasoning may increase confidence while taking longer; the model should permit that tradeoff.

Evidence: [signal scheduling](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L1001), [timed defense evaluation](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L1084), [fixed response delays](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L2553).

### 6 Virtual patching needs an explicit place in the traffic path

**Priority 1.** Exercise patch coverage is a seeded boolean: a log-derived opening is uncovered, while another opening has a 65% coverage draw. Ordinary CVE handling uses a mitigation lookup, an asset-interface check and a portal coverage hash. These assumptions do not fully establish that the relevant request crosses an enabled enforcement point that can inspect and match it. The lookup can apply to internal targets without an explicit inline inspection path.

**Suggested fix.** Attach enforcement points to routes and services. Specify protocol visibility, TLS termination where relevant, installed rule, protected endpoint, matching action, deployment time and failure mode. Distinguish an installed rule from a new rule that SOC proposes or deploys during the incident. Add legitimate traffic to reveal false blocks and availability costs. If the scope remains WAF-only, label the comparison “WAF virtual patching”; virtual patching also includes other enforcement mechanisms.

**Acceptance check.** The same vulnerable service must have different outcomes when its attack traffic traverses a covered control or takes an uncovered path. Correctly authorized activity must be distinguishable from the prohibited action. A newly deployed rule must not protect earlier requests retroactively.

Evidence: [defense evaluation](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L842), [exercise coverage](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L1293). OWASP describes virtual patching as an enforcement layer that intercepts exploitation and discusses mechanisms beyond WAFs and the importance of parsing. [OWASP virtual patching guidance](https://community.owasp.org/Virtual_Patching_Best_Practices).

### 7 A display budget changes simulated damage

**Priority 1 and a concrete comparison bug.** Baseline allows up to three reached assets per layer; defense modes reduce the data-layer cap to one. The traversal cap stops successful state changes, rather than merely hiding extra rendered nodes. It can therefore make a defense appear to reduce impact even when that defense does nothing.

At seed 42, the REvil profile reaches two data-layer assets in baseline and one in SOC mode, with zero control events. This is an effect of the budget, not containment.

**Suggested fix.** Separate simulation limits from rendering limits. Use identical computation and attack budgets across compared defense modes. Draw a summarized subset of the complete result if needed. If a simulation is genuinely truncated, mark its outcome incomplete rather than secure or contained. Retain a reasoned event for actions prevented by containment; currently a contained transition can return without a suppressed-action event.

**Acceptance check.** With no matching signal and no other active control, baseline and SOC must produce the same reachable assets and impact. Changing diagram density must not change simulation outcomes.

Evidence: [data-layer cap](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L1119), [containment early return](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L1039).

### 8 Infrastructure variety is broader than the modeled causal variety

**Priority 2.** The generator has useful product mappings and directed relationships, but progression is restricted to adjacent layers. It cannot naturally express many same-tier, identity-mediated, direct-to-cloud-data or returning paths. The 100-reference catalog selects one of four context profiles; the chosen CVE is displayed as a reference, while the estate generator receives the preferred ingress group rather than that CVE's full applicability conditions.

This is acceptable for contextual references, but it should not be interpreted as 100 independently modeled attack scenarios. Similarly, the Git-to-IdP branch is an authored illustration whose evaluated result is a log read, not the depicted downstream privilege chain.

**Suggested fix.** Start with a small set of coherent estate archetypes: legacy enterprise identity and endpoints, public web application with internal data, cloud/SaaS identity, and CI/CD with secrets. Specify network routes, identities, privileges and sensor/control placement for each. Draw layout layers from that model rather than constraining the model to the layout. For each reference, declare whether it is context only, a modeled weakness, or a complete modeled chain. Require explicit credential and privilege transitions before drawing a successful Git-to-IdP path.

**Acceptance check.** Each successful hop must explain both reachability and authorization or exploitation. Changing a catalog reference alone must not imply that its CVE has been simulated. Different archetypes must produce meaningfully different attack and defensive opportunities.

Evidence: [relationship generation](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L1405), [layer progression](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L1205), [reference selection](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/wire.html#L1045), [illustrative branch](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/wire.html#L762).

### 9 The comparison needs independent controls and explicit outcomes

**Priority 2.** The current UI offers baseline, virtual patch, SOC, and SOC plus canary. That can demonstrate the incremental effect of canary signals under one SOC policy, but it does not expose canary-only detection or patch-plus-SOC interactions. The older comparison engine has additional combinations and failure cases, creating two implementations with different semantics.

The main success variable is any `data_read`, and the UI labels it a protected record read. The outcome has no independent record sensitivity, volume, exfiltration destination, encryption or business-disruption model. Also, `finishRun()` assigns the `contained` visual class whenever no data read occurs, including cases where access was never possible or exploration was truncated. Its textual explanations are more nuanced than that binary visual state.

**Suggested fix.** Make patching, canary deployment and response policy independent settings on one event engine. Provide a compact comparison matrix over the same estate and attacker assumptions. Keep canary-only detection separate from active response. Track initial access, privilege gained, first sensitive read, volume accessed or exported, containment scope, disruption and unresolved branches as separate outcomes. Report “no viable path”, “policy denied”, “prevented”, “contained before impact”, “contained after impact” and “incomplete” distinctly.

**Acceptance check.** Removing the canary signal from SOC plus canary must reproduce the same SOC policy. Every claimed prevention must name the intervention that caused it. A case with no viable baseline path must not count as a defensive success.

Evidence: [active controls](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/wire.html#L529), [result rendering](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/wire.html#L953), [separate comparison evaluator](https://github.com/kostchei/artex_sandbox/blob/286cf02952b87b0525ee4c9cc718543f54a759cd/js/wire-engine.js#L2726).

## Evidence from model sensitivity checks

The existing regression suite passed. A separate read-only script exercised the current wire engine on seeds 1 through 200, using `generateEstate({seed, seedExercise: true})`. It does not execute attacks or measure Docker performance. These are observations about the simulator's internal behavior, not real-world defense effectiveness estimates. The sweep does not reproduce the UI's catalog draw or its rejection of an unchanged appliance roster.

### Runs with any data read out of 200 estates

| Attacker preset | Baseline | Virtual patch | SOC | SOC plus canary |
| --- | ---: | ---: | ---: | ---: |
| LockBit | 164 | 88 | 0 | 0 |
| Conti | 164 | 88 | 4 | 0 |
| BlackCat | 164 | 88 | 164 | 164 |
| Hive | 164 | 88 | 0 | 0 |
| REvil | 164 | 88 | 164 | 164 |
| ARTEX-like | 164 | 88 | 164 | 5 |

These sharp differences largely reflect the preset signal and timing assignments. The five ARTEX-like reads under SOC plus canary also matter: the canary does not protect every alternative branch. It would be inaccurate to describe it as universally successful.

Additional checks found:

- Removing only exercise findings reduced ARTEX baseline data-read runs from 164 to 8. This shows how much the current demonstration depends on the authored exercise path; it is not an estimate of vulnerability prevalence.
- Replacing every relationship's required source capability with an unavailable capability still allowed an exercise record read in 163 estates. The exercise bypass is observable behavior, not merely a theoretical concern.
- LockBit and ARTEX baseline event sequences were identical in all 200 estates when timestamps were removed.
- All 200 ARTEX SOC-plus-canary runs emitted a canary signal while returning no canary asset ID, consistent with the active signal shortcut.
- Three estates showed a smaller reached-data-asset count under REvil SOC despite no response events. Seed 42 gives the two-versus-one example described above.
- At seed 1, ARTEX's record read occurred at 4,440 modeled seconds, its boundary signal at 4,390 seconds, and enforcement at 4,450 seconds: the fixed ten-second miss.

Reproduce from the repository root with `node scripts/test-wire-model.cjs` and `node scripts/review-comparison.cjs`. The second script and its saved output are [review-comparison.cjs](../scripts/review-comparison.cjs) and [comparison-review-evidence.json](comparison-review-evidence.json).

## Recommended simulation design

Keep the diagram and replay interface. Underneath, use a discrete-event model with five explicit inputs:

1. **Estate state:** assets, routes, permissions, weaknesses, data and deployed sensors/controls.
2. **Attacker policy:** initial knowledge and access, available actions, concurrency, decision cost, discovery, errors and adaptation.
3. **Telemetry policy:** which actions generate events, collection delay, loss, noise and identity attribution.
4. **Defense policy:** patch coverage, decoy placement, investigation, approvals and response capabilities.
5. **Calibration assumptions:** historical stage durations, conditional probabilities, uncertainty ranges and provenance.

An attacker action should create an observation or state change; that action may generate telemetry; telemetry may trigger investigation and a response; an effective response changes which later actions remain possible. The attacker should know only what it has discovered, while the engine can retain the full estate as ground truth. The same event history should drive the diagram, tickets and result summary.

A practical first scenario set should include a covered known exploit, an uncovered credential path, an early canary touch, a late touch, an untouched decoy, a missing sensor, a wrong-scope response, a failed enforcement action, and an estate with no viable path. Add a multi-session case and a benign administrative workflow so concurrency and false containment have consequences. These scenarios provide useful contrasts without needing hundreds of product labels.

### Calibration and comparison rules

- Give every timing input a milestone definition, source, affected population and uncertainty range. Distinguish sourced values from expert assumptions and scenario choices.
- Preserve correlations: environments with better identity controls may also have better telemetry; attack steps cannot finish before their prerequisites. Avoid making every input an unrelated random draw.
- Use overlapping pace ranges where evidence permits and retain slower or failed agentic runs and fast conventional automated runs.
- Compare defense settings on the same estate, starting access, attacker policy and underlying random draws. Permit later attacker behavior to diverge when a defense changes what the attacker observes.
- Publish sensitivity results by archetype and assumptions. If a small change to canary placement or response latency reverses the result, show that dependence rather than presenting a universal winner.
- Keep historical breakout, simulated time to sensitive read, local lab elapsed time and organizational breach-discovery time separate. The existing comparison document's opening table and millisecond-response conclusions should be reconciled with its later caveats. Historical anchors can remain; the unlike intervals should not be used to infer a common speed ratio or response requirement.

The simulation can be realistic enough for structured decisions before every input is empirically calibrated. The important condition is that uncertain assumptions are visible and the conclusion remains appropriately conditional.

## Delivery sequence

| Step | Changes | Completion criterion |
| --- | --- | --- |
| 1 Correct attribution | Equal traversal caps; explicit incomplete outcomes; causal exercise prerequisites; distinct result labels. | No defensive credit without an effective intervention or explicit access policy. |
| 2 Repair the comparison | Independent attacker and telemetry settings; independent defense switches; configurable stage and response timings. | Actor names and presentation settings cannot determine protection. |
| 3 Add behavioral realism | Explicit decoys, investigation and enforcement states, worker scheduling, discovery and adaptation. | Outcomes follow the event history and explainable state changes. |
| 4 Improve calibration | Coherent estate archetypes, documented historical inputs, scenario weights and sensitivity analysis. | A reviewer can identify which assumptions support a conclusion and which changes reverse it. |

## Scope and separate Docker context

This review covers the active `main` wire simulation, its JavaScript engine, reference catalog, documentation and regression checks. The Docker stub and defender code were inspected as supporting context; the services and live ARTEX agent were not run, and no production environment was assessed. Browser layout was not exercised. These limits do not prevent assessing the simulation rules described above.

The Docker lab should remain a separate teaching or integration example. Its prescribed next-hop chain and synchronous telemetry do not establish realistic field timing, and are not the basis of the clock critique. If that lab's results are used as supporting evidence, address three separate implementation issues: `defender/app.py:160` marks containment before revocation succeeds and later suppresses errors; `stubs/app.py:23` recognizes token format without an issuance/authorization registry; and the blocking WAF rule matches the presence of `include_tokens`, including a benign false value. Those issues warrant lab-specific fixes, but improving the simulation does not depend on turning the lab into a real-world attack benchmark.

**Recommended decision:** retain the sandbox as the presentation foundation, fix the causal and comparison defects first, and then calibrate stage behavior and defense conditions. The objective should be an explainable range of plausible outcomes under stated assumptions, rather than one recurring story in which agentic speed defeats SOC and an early canary restores protection.
