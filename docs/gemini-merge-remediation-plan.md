# Plan for findings after the Gemini merge

Status: implemented for the four merge-review findings; see [implementation and validation](remediation-implementation.md). The sections below preserve the original acceptance plan and broader design intent. Remaining calibration and model boundaries are recorded in the implementation report.

Date: 16 November 2026. Reviewed baseline: `8aeae9b9e12adcf35ae2bd8e7a35e1a36171370c` on local `main` after the fast-forward merge of `artex-gemini`.

## Scope and evidence

Address four findings from the merge review: unequal exploration limits, misleading containment presentation, predetermined timing outcomes, and overlapping diagram labels. Preserve deterministic replay and align defense choices with the six-phase product direction recorded in [AGENTS.md](../AGENTS.md).

The user's latest direction in [AGENTS.md](../AGENTS.md) takes precedence over older design documents. The existing [engineering specification](wire-improvement-engineering-spec.md) supplies supporting technical detail. This plan defines a bounded delivery sequence for the reviewed findings; it does not claim that the merged branch implements that specification in full. In particular, varying timers alone would not satisfy the requirement for outcomes caused by actions, evidence and interventions. Historically informed animation and the cumulative stopwatch remain core product features.

### Alignment with the six-phase product model

Before implementing these fixes, verify the upstream foundations: a plausible linked enterprise (phase 1), applicable CVEs/KEV membership and a viable vulnerable walkthrough (phase 2), and attacker flows that obey those prerequisites (phase 3). Equal exploration accounting protects comparisons of those flows. Causal scheduling must preserve the historical clock and animation (phase 4). Result classification must explain the effect of controls (phase 5). Layout work must preserve scenario identity and deterministic regeneration/replay behavior (phase 6).

The required defense comparisons are baseline, virtual patching, agentic SOC, and canaries plus **both** agentic SOC and virtual patching. The current five UI choices include canaries alone and SOC plus canaries, but do not expose the required full combination. Add that combination to the implementation backlog and verify its engine semantics; do not assume that an existing mode named `combined` supplies the correct behavior. Additional comparison modes may remain. Test that the full combination applies the same patch coverage and SOC policy as the individual controls, with decoy evidence entering that same response lifecycle.

Keep a deliberately vulnerable walkthrough for demonstrating a credible breach, with separate exploratory estates that may have no viable path. Historical timings must retain source/milestone definitions and visible modeling assumptions. Each implementation step must demonstrate that the diagram, event history, stopwatch and result agree, and that changing defenses reuses the enterprise while New Infra generates a fresh one.

Validation already performed on the merged revision:

- The model regression suite passed.
- Browser checks exercised both attacker choices, all five defense modes, Results and Replay, with no page errors.
- A 200-seed sweep checked for disagreement between the data-read summary and protected Layer 3 reads, and for successful child events preceding successful source access; neither check found a mismatch in that sample.
- Visual inspection at 1440 × 900 showed overlapping labels in dense clusters. This was a sampled layout, not a viewport or seed coverage test.

These checks establish a working baseline. They do not establish realistic defense effectiveness or cover the defects below.

## 1. Equalize exploration and separate display limits

Priority: high. Primary implementation: `simulateEstate()` in `js/wire-engine.js`.

### Current defect

The data-layer cap is `MAX_SUCCESS_PER_LAYER` for baseline and standalone canaries, but one for other defenses. A run can therefore reach fewer data assets without a defense intervention. The scheduler also permits 40 single-worker waves versus 16 three-worker waves; waves are not a common unit of exploration allowance. Display-driven source and layer caps truncate the model itself.

### Proposed change

1. Define one exploration policy shared by all defense modes and both attacker profiles. Use a total evaluated-transition budget with documented counting rules, plus deterministic cycle/revisit protection. Keep worker concurrency separate from that allowance.
2. Apply the same policy to a paired comparison. Defense actions may change reachable state and attacker choices, but must not change the allowance implicitly.
3. Move limits on displayed paths, highlighted nodes and ticket counts into the renderer. Preserve the complete modeled event history and impact counts within the common safety budget.
4. Report budget exhaustion independently of impact: include the budget name, used allowance and pending work. A read does not make remaining unexplored branches complete. Audit the existing `frontier.length > 0 && !dataReached` truncation rule.
5. Treat suppressed transitions after effective containment as skipped work with an explanation, rather than attempted attacks blocked by a new control. Define their budget accounting explicitly.

### Acceptance checks

- On a controlled fixture with multiple readable data assets and no applicable intervention, baseline, patch and SOC produce the same access results and budget accounting under fixed attacker actions.
- An untouched canary changes neither access nor exploration allowance.
- Changing only worker count leaves the total allowance unchanged; any changed result must be attributable to scheduling and modeled state changes.
- Reaching one data asset while pending work exceeds the allowance reports both impact and incomplete exploration.
- Reducing rendered highlights does not change engine events, reads or completion state.

## 2. Derive result text and styling from explicit evidence

Priority: high. Primary implementation: engine summary and `finishRun()` in `wire.html`.

### Current defect

`finishRun()` assigns the `contained` class whenever `dataReached` is false. That includes no viable access, WAF prevention, alert-only runs and unfinished exploration. Counts of contained sessions do not establish that every relevant branch was contained.

### Proposed change

1. Add a shared result classifier driven by engine facts. Return separate fields for impact, completion and intervention evidence; have the browser consume that result rather than infer it again.
2. Keep distinct descriptions for no access established, prevention by a named control, containment before impact, containment after impact, alert without response and incomplete exploration. Permit combined statements such as “Record read; exploration incomplete.”
3. Require successful enforcement against the relevant session before describing it as contained. Scheduled response, signal receipt and decision events are insufficient. In a multi-session run, report partial containment unless all relevant active sessions are accounted for.
4. Use a neutral visual state for unexplained absence of a read, alert-only outcomes and incomplete results. Retain impact styling when a read has already occurred.
5. Show skipped-after-containment events separately from attempted-and-prevented events, consistently across node badges, tickets and totals.

### Acceptance checks

Use small fixtures for no initial access, WAF prevention, untouched decoy, alert-only decoy, containment before read, containment after read, one contained and one active session, and truncation with/without a read. Assert classifier output and browser text/style agreement. No fixture receives containment credit from absence of a read alone.

## 3. Replace the fixed timing race with causal scheduling

Priority: high; larger than the preceding fixes. Primary implementation: `wireTiming()`, `simulateWireRun()`, `recordTelemetry()`, `signal()` and transition scheduling.

### Current defect

ARTEX stage times are fixed at 50 and 35 seconds before the read while enforcement takes 60 seconds. On the corresponding signaled path, this encodes a late response. Total duration varies by seed, but the decisive gap does not. Queue batches also do not yet constitute worker scheduling with action start/finish times.

### Proposed change

1. Define actions with prerequisites, start/completion times, observations and state changes. Process action completions and defense events through one deterministic chronological queue, with a documented tie policy.
2. Schedule concurrent workers only when prerequisites and worker capacity permit. Associate sessions explicitly with actions and enforcement. A later-processed early canary must not leave an already-scheduled later response uncorrected.
3. Generate telemetry from the action and deployed sensors. Route canary evidence through the same decision and enforcement policy as other evidence; decoy interaction alone does not establish instantaneous session containment.
4. Give response stages separate collection, decision and enforcement behavior, including scope, authority and failure. Only confirmed enforcement changes subsequent access.
5. Keep historical duration context with explicit milestone definitions and provenance. Label stage allocations and response latencies as assumptions. Remove the fixed offsets as the general comparison rule; preserve them only as an explicitly authored timing-race teaching fixture if still useful.
6. Separate actor names, capability profiles, observation settings and timing inputs. Use stable keyed random draws so changing one setting does not scramble unrelated assumptions. Audit adaptive WAF bypass and detection multipliers where they directly predetermine the intervention being compared; document remaining realism limitations.
7. Explain the actual sequence in Results: action, signal, decision, enforcement, scope and impact. Show the signal-to-impact interval when it is meaningful. Do not imply a universal winner from one scenario.

### Acceptance checks

- Holding total duration constant, changing a causal action schedule or sensor placement can change the response opportunity.
- Fast conventional automation can complete before response; an agentic attacker can be contained before impact. Neither result follows solely from the actor name.
- Identical actions, sensors and random inputs produce identical evidence when only the displayed actor name changes.
- Enforcement before action completion prevents the modeled effect according to the documented cancellation policy; enforcement after a read preserves that impact. Exact ties have a deterministic tested meaning.
- Early, late and untouched decoys, wrong-scope response, failed enforcement and merged/multiple-session paths behave distinctly.
- No action starts before required access exists. Each worker executes within its capacity. Replay and Results consume the same event history.

## 4. Make dense layouts readable

Priority: medium. Primary implementation: `layoutGraph()`, `.node-label`, active badges and tooltip/detail rendering in `wire.html`.

### Proposed change

1. Compute node, label and active-badge bounding boxes after fonts and icons load. Use deterministic placement within layer bands and minimum spacing; resolve collisions with nodes as well as text.
2. Prefer additional canvas height and scrolling when a dense estate cannot fit at readable size. Recompute positions on resize and redraw wire endpoints from the resulting node positions.
3. Use concise persistent labels with full product/version/finding details on keyboard focus and pointer selection. Give the selected node's details a stable panel instead of stacking large badges over nearby labels.
4. Preserve asset IDs, edges and simulation state. Layout changes must not regenerate the estate or alter comparison outcomes.

### Acceptance checks

- Check fixed sparse and dense seeds at 1440 × 900, 1280 × 720 and a narrow 390 × 844 viewport. Scrolling is acceptable; clipped or inaccessible controls and labels are not.
- Measure persistent label collisions after layout and after resize. Dense fixtures must have no intersecting persistent label boxes; full details remain accessible when labels are shortened.
- Focus/selection exposes the complete asset details with readable text; selected badges and the ticket panel do not obscure required controls.
- The same seed and viewport produce stable layout. Resizing and switching defenses preserve topology, estate state and modeled outcomes.

## Delivery order and review gates

See the [Codex and Claude branch review](other-branch-review.md) for reusable corrections, compatibility issues and fresh targeted evidence. Validate coverage declarations and complete action orders as upstream prerequisites; adapt the selected branch fixes to Gemini rather than merging their older engine wholesale.

| Step | Deliverable | Review gate |
| --- | --- | --- |
| 1 | Common exploration accounting and display separation | Equal-allowance fixtures pass; unfinished work is reported even after impact. |
| 2 | Shared outcome classifier and consistent presentation | Outcome fixtures and browser text/style checks pass. |
| 3 | Causal event scheduling and defense lifecycle | Scheduling, scope, tie, decoy and enforcement fixtures pass; sensitivity runs show conditional outcomes. |
| 4 | Collision-aware layout and accessible details | Fixed viewport/seed checks and visual review pass. |

Deliver each step as a separate reviewable change. Reuse useful Codex fixes for caps and neutral result styling as references, but reconcile them with the merged Gemini behavior rather than applying them without review. Claude's explicit-coverage checks are a related follow-up, outside these four findings unless the scheduling work requires them.

For implementation validation, run `node scripts/test-wire-model.cjs` after each engine change. Replace assertions that merely encode old outcome frequencies with fixtures for causal invariants; record aggregate differences for investigation rather than forcing an expected defense ranking. At each integration gate, exercise both attackers and all five modes with Replay, Results and New Infra; check console errors, deterministic replay, unchanged topology across paired comparisons and the static launcher redirect.

Record manifests, seeds, inputs and result summaries for any sweep so failures are reproducible. Update README assumptions when behavior changes. This document neither implements nor authorizes a remote push or deployment.
