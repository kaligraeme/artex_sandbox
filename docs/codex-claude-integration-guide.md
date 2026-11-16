# Implementing the Codex and Claude improvements on Gemini

Date: 16 November 2026. Baseline: local `main` at `f386794`.

This is an implementation and completion guide, not a request to apply the old branches wholesale. Gemini supplied the feature foundation. Selected Codex and Claude improvements have already been adapted into local main in `f386794`; the remaining work below strengthens their contracts, evidence and tests. This document adds no application changes.

The quoted branch comparison describes the earlier Gemini revision `8aeae9b`, before that integration. Do not interpret its missing-coverage and traversal-cap findings as the current implementation status. Remote publication is separate: the last push attempt failed with an account permission error, so this guide makes no claim that GitHub main contains these local changes.

## 1. Product constraints

Follow [AGENTS.md](../AGENTS.md). Preserve the six-phase experience: generate a plausible enterprise; assign applicable weaknesses and a viable vulnerable walkthrough; show conventional or ARTEX-like attack behavior; animate it with the historical-context stopwatch; compare defenses on the same enterprise; regenerate or replay deterministically.

The required full defense combines virtual patching, agentic SOC and deployed canaries. Standalone canaries and SOC-plus-canary are useful additional views. Keep animation, topology, clock, tickets and final results tied to the same event history. Missing reads, absent routes and exhausted exploration must not receive defensive credit without evidence.

## 2. Integration inventory

Source references: Codex `96e504a` and Claude `311c6d8`. Their implementation base predates Gemini's changes.

| Improvement | Origin | Current local status | Completion work |
| --- | --- | --- | --- |
| Equal traversal limits across defenses | Codex | Implemented more broadly: one 1,000 evaluated-transition ceiling; per-layer/source display caps removed. | Protect counting semantics with precise no-intervention and boundary fixtures. |
| Explain steps suppressed by containment | Codex | Implemented as `suppressed` effects, distinct from new blocked attempts. | Verify queued versus in-flight suppression consistently in metrics, animation and tickets. |
| Honest incomplete/no-containment presentation | Codex | Shared `classifyRun()` drives result text and styling. | Add exhaustive small outcome fixtures and direct assertions for neutral browser states. |
| Five missing CVE coverage entries | Claude | Added to `KEV_MITIGATION_RULES`. | Audit source evidence, applicability and enforcement-path assumptions; strengthen exact outcome tests. |
| Reject missing modeled coverage | Claude | Checked by estate validation before playback, including baseline; direct defense lookup also rejects missing entries when reached. | Define explicit unknown/unsupported states and exhaustively validate the declarable catalog. |
| Remove invented HTTPS defaults | Claude | Removed from connection inference and defense evaluation. | Document direct-helper preconditions and enforce a consistent validated boundary. |
| Deterministic action ordering | Claude | Eager validation checks omitted, duplicate and unknown IDs, including single-item cases. Missing or empty order uses asset declaration order. | Add a true one-asset regression fixture and document empty-order semantics. |
| Realism review and sensitivity analysis | Claude | Findings considered; active-engine sweep added as `review-remediation.cjs`. | Preserve the original review as revision-labelled historical evidence and improve manifests for new probes. |

### Progress after the UI freeze

Estate validation now rejects empty, non-string and whitespace-padded interface identifiers and relationship protocols. The remediation suite covers these cases, a genuine single-asset order containing an unknown ID, and equivalent absent and empty orders. Route protocol compatibility remains an action-level accessibility decision. `evaluateDefense()` documents and enforces its validated-target/action boundary.

The current sweep reports its Git revision and whether the working tree is dirty, its generation and simulation defaults, and emits the full estate and run parameters when an invariant fails. Canary signals are checked against both actual decoys and deployed decoy IDs. Paired probes vary response latency, response scope and telemetry placement. The original Claude review and output are preserved separately and identify reviewed revision `286cf02`; their counts remain historical evidence.

Scheduled suppression events now include `suppressionPhase` (`queued` or `in_flight`), `enforcementSec` and `scheduledEffectSec`. The focused tests exercise both phases. Suppressed work is excluded from both `attemptedTransitions` and `evaluatedTransitions`, including an in-flight effect cancelled after dispatch; `suppressedTransitions` counts those events separately. One allowance unit is charged per unique source, target and relationship transition reaching action evaluation, including an ineligible transition. Multiple candidate actions on that transition share the unit. Duplicate transitions, suppressed transitions and undeployed or disabled decoys do not consume it. The scheduler's common default remains 1,000, independent of worker count and display limits.

All CVEs reachable from the executable catalog and variant mappings now require reasoned WAF and SOC states. The accepted states are `modeled`, `not_applicable`, `unsupported` and `unknown`; only `modeled` can mitigate. Exact fixtures cover matching and unrelated routes for the four imported HTTP examples, plus the non-HTTP Zyxel path. The outcome table is covered directly through `classifyRun()` fixtures, and the browser suite asserts the neutral result as well as the existing defense matrix and replay path.

Already-delivered integration also supplies causal worker scheduling, explicit response failure/authority, real decoy validation, the full layered defense button and readable scrolling layouts. These are dependencies to preserve when completing the work; they should not be replaced with older branch implementations.

## 3. Work package A — Coverage declarations and applicability

**Phases:** enterprise weaknesses and defense comparison (2 and 5). **Priority:** first remaining package.

**Files:** [engine](../js/wire-engine.js), [reference catalog](../assets/wire-defense-catalog.json), [model tests](../scripts/test-wire-model.cjs), [remediation tests](../scripts/test-remediation.cjs). Add a small evidence catalog if needed rather than embedding long source narratives in renderer code.

### Implementation

1. Enumerate the union of all CVEs declarable through reviewed product examples, variant mappings, generation presets and imported scenarios. Sampling generated seeds alone is insufficient to establish completeness. Keep reference-only catalog entries separate from executable findings.
2. For each executable CVE, require a product/version/configuration mapping, protocol and interface prerequisites, a primary advisory reference, and a separate KEV-membership record. Do not equate CVE existence with KEV membership.
3. Audit the five imported declarations: `CVE-2020-3452`, `CVE-2021-20016`, `CVE-2022-1040`, `CVE-2023-28771`, `CVE-2024-24919`. Their presence in code is established; this document does not independently validate every mitigation claim.
4. Record the WAF enforcement point, route/protocol inspected, rule or payload assumption, and uncovered bypass conditions. A CVE-specific boolean is insufficient evidence that every deployment is protected.
5. Separate SOC observability from actual containment. Coverage metadata can describe evidence a sensor could produce; the active scheduler must continue to require collection, decision, authority and successful enforcement before cancelling an effect.
6. Introduce an explicit coverage state contract: modeled, not applicable, unsupported or unknown, each with a reason. These are proposed states, not fields already implemented. A missing declaration remains a configuration error. Unknown coverage must not become a success claim or an inferred modeled bypass rate.
7. Reject invalid authored scenarios during validation. For an intentionally unknown scenario, preserve its identity and display the unresolved assumption; do not silently regenerate infrastructure or invent an effective control.

### Acceptance

- Every declarable executable CVE has complete WAF and SOC declarations or an explicit reasoned unknown/unsupported state.
- Each of the four imported HTTP-path examples has exact fixtures for a covered matching rule and an uncovered route. Do not accept either shielded or bypass indiscriminately as a passing assertion.
- A non-HTTP fixture stays outside HTTP WAF inspection even with a modeled rule elsewhere in the estate.
- Wrong product, unaffected version, missing exploit condition and incompatible route cannot establish access.
- Unknown coverage earns no prevention or containment credit. A missing declaration fails before animation, including baseline and canary-only runs.
- Add a fixture showing that a declared SOC detection opportunity alone does not instantaneously stop an attack.

## 4. Work package B — Ordering and interface contracts

**Phases:** infrastructure and replay (1, 3 and 6). **Priority:** alongside package A.

### Implementation

1. Preserve eager `validateEstate()` checks. Never rely on a sort comparator to discover a missing rank; Claude's original implementation missed single-item cases.
2. Specify that absent or empty `actionOrder` means stable asset declaration order. A supplied nonempty order must contain every retained asset exactly once and no other IDs.
3. Define the boundary for exported helpers such as `evaluateDefense()` and connection inference: either accept only validated inputs or validate their required fields directly. Pick one explicit contract and test it. Do not restore inferred HTTPS as error recovery.
4. Check interface identifiers, route protocol compatibility and source capabilities at the appropriate validation/action boundaries. Distinguish structurally invalid topology from a valid but inaccessible route.
5. Keep validation messages actionable. The browser should identify an invalid scenario without displaying an implementation stack trace or replacing it with a different random estate.

### Acceptance

- A genuine one-asset scenario with an unrelated declared order ID is rejected before traversal.
- Omitted IDs, duplicate IDs, unknown IDs and malformed order types fail; absent/empty orders replay deterministically.
- Missing, empty and malformed interface declarations fail at the documented boundary.
- Rendering, resizing and selecting a different defense do not change asset ordering or the estate manifest.

## 5. Work package C — Fair exploration and accounting

**Phases:** attack flow and defense comparison (3 and 5). **Priority:** after validation foundations.

### Implementation

Retain the common total transition ceiling. Document the counting unit precisely: what consumes allowance, how revisits are deduplicated, how multiple eligible actions on one transition are represented, and how skipped work differs from evaluated work. Keep simulation allowance independent of worker count, attacker label, defense mode and rendered highlights.

Distinguish three cases in the event contract:

- A queued step skipped before it starts because its session is contained.
- An in-flight effect cancelled when enforcement becomes effective.
- An attempted action prevented by a matching control at its enforcement point.

Current code uses `suppressed` for the first two. Preserve that distinction in accounting and explain the cause using start/effect/enforcement timestamps. Decide whether attempted-action metrics should count started-but-cancelled work separately; document the decision rather than changing counters implicitly.

### Acceptance

- A no-intervention fixture with multiple readable targets gives identical access results across defense choices under fixed actions and shared inputs.
- Lowering a rendering limit never changes engine events or impact.
- At the exploration ceiling, a completed read plus pending work remains both impacted and incomplete.
- Changing worker count alone leaves the total allowance unchanged. Changed outcomes must follow scheduling/state differences.
- Duplicate/revisited transitions and zero-duration actions cannot evade termination protection.
- Suppressed work produces an explanation without a new attack pulse or an extra virtual-patch block.

## 6. Work package D — Evidence-based results and browser consistency

**Phases:** animation and comparisons (4 and 5). **Priority:** paired with package C.

Use `classifyRun()` as the source for impact, completeness and containment facts. Audit any remaining HUD/ticket calculations that independently infer those facts. Confirmed enforcement must refer to a relevant active scope; one contained session does not establish that every branch is safe.

| Fixture | Required explanation |
| --- | --- |
| No usable initial access | No access established; neutral result, no containment credit. |
| WAF prevents an applicable action | Name the control and attempt; preserve any unrelated access. |
| Canary alerts without response | Alert-only result; no containment styling. |
| Early enforcement | Suppressed effect with matching scope and causal times. |
| Read before enforcement | Preserve the read and report later containment. |
| Wrong scope, missing authority or failed enforcement | No containment credit for the affected attack path; explain the failure or mismatch. |
| One contained and one active session | Partial containment. |
| Allowance exhausted before/after a read | Incomplete exploration, with independent impact status. |

For each fixture, assert engine facts, final HUD text/style and relevant tickets. Test both animated playback and Results so skipping the animation cannot change the outcome. Tie behavior remains explicit: enforcement at an action's completion time cancels its effect.

## 7. Work package E — Reproducible realism review

**Phases:** all six. **Priority:** final integration gate.

1. Preserve Claude's original review and probe output under their reviewed baseline `286cf02`. Import them as historical evidence if needed, with an introductory revision note; do not publish the old 200-seed counts as Gemini/current results.
2. Extend the current `review-remediation.cjs` output to include the tested revision, scenario/preset, seed, attacker policy, control settings, timing assumptions and exploration policy. Capture the exact failing manifest for every invariant failure.
3. Check canary signals against deployed decoy IDs. Do not use the legacy singular `canaryAssetId` field alone as proof that no decoy exists.
4. Build a true no-signal fixture by controlling sensors and evidence, not by selecting a gang name. Do not rerun the obsolete exercise-removal probe as evidence about paths that no longer use exercise findings.
5. Sweep coverage, signal placement, response latency and scope independently on paired scenarios. Keep historical total-duration context separate from synthetic stage allocations and observed local runtime.
6. Report conditional outcomes and sensitivity. Do not force every aggregate defense count to improve monotonically or tune parameters until one attacker always wins. Added decoys or responses may change scheduling; investigate and explain such differences.

## 8. Implementation sequence and release gates

| Change | Deliverable | Gate |
| --- | --- | --- |
| A | Exhaustive coverage contract, evidence records and exact control fixtures | No silent coverage gaps or unsupported effectiveness claims. |
| B | Explicit validation/helper boundary and one-asset regressions | Malformed scenarios fail before playback; valid replay stays stable. |
| C + D | Consistent exploration/event accounting and classified presentation | Same event history drives metrics, animation, clock, tickets and Results. |
| E | Revision-labelled manifest sweep and review evidence | Failures reproduce; historical and current measurements remain separate. |

Make each change reviewable with its focused fixtures and documentation. When editing shared engine/UI contracts, deliver both sides together. Do not merge an old engine version over Gemini to obtain a small fix.

Run the model checks from the repository root:

```powershell
node scripts/test-wire-model.cjs
node scripts/test-remediation.cjs
node scripts/review-remediation.cjs
git diff --check
```

Then run `node scripts/test-browser-remediation.cjs` with Playwright Core available. Set `PLAYWRIGHT_CORE_PATH` if the package is installed externally and `EDGE_PATH` when the executable differs. Preserve coverage of both attackers, all six modes, Replay, Results and New Infra at desktop and narrow widths. Add direct outcome-fixture assertions where package D requires more than the existing generic browser matrix.

Previously recorded results for `f386794` are in [remediation implementation and validation](remediation-implementation.md): model suites, 7,200 sampled runs and 108 browser combinations. Those are existing implementation evidence, not fresh test results from this documentation-only pass.

## 9. Scope boundaries and handoff

Completion means the Codex fairness/reporting intent and Claude explicit-configuration/review intent are implemented with the stronger tests above. It does not by itself validate every generated enterprise archetype, establish field attack timing, prove product effectiveness or finish a multi-principal SOC model.

Retain the current [timing assumptions](timing-assumptions.md), six-phase direction and full layered comparison. Add richer infrastructure archetypes, CVE evidence auditing and attacker discovery as explicit subsequent roadmap work. Update this guide's status table after each implemented change so completed work is not repeatedly proposed.
