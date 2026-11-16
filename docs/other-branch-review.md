# Review of Codex and Claude improvements after the Gemini merge

Date: 16 November 2026. Documentation only; no branch changes applied.

Historical review of the pre-remediation baseline. Selected findings were subsequently addressed in local `main` at `f386794`. Use the [Codex and Claude integration guide](codex-claude-integration-guide.md) for current implementation status, remaining work and acceptance checks.

Compared local `main` / Gemini at `8aeae9b`, Codex at `96e504a`, and Claude at `311c6d8`. These are the fetched local revisions, not a fresh remote audit. Evaluate adoption against the user's six-phase direction in [AGENTS.md](../AGENTS.md) and the [remediation plan](gemini-merge-remediation-plan.md).

## Recommendation

Incorporate the intent of Codex's fairness and reporting fixes and Claude's explicit coverage checks. Adapt their code to the merged engine. Neither branch delivers a complete alternative to Gemini or resolves the full six-phase workflow. Their shared engineering specification and critique are already identical to the copies on Gemini; importing them again adds no design content.

## Codex: useful corrections, limited scope

| Change | Benefit and phase | Adaptation needed |
| --- | --- | --- |
| Equal per-layer traversal caps | Phase 5: removes one artificial reason defenses reach fewer data assets. | Retain Gemini's standalone-canary behavior. Extend this to a shared total exploration allowance; the fix alone retains display-driven model caps and unequal worker-wave limits. |
| Explicit `suppressed` event after containment | Phases 3–5: explains why an attack step did not happen. | Gemini already emits `contained` events, increments attempts/blocks for them and uses different timing/tie behavior. Replace that accounting consistently across engine, animation and tickets. Decide equality semantics explicitly rather than inheriting Codex's strict `<` or Gemini's `<=` accidentally. |
| No probe animation for suppressed steps | Phase 4: stops presenting unattempted activity as a new attack. | Coordinate with Gemini's event renderer; it currently recognizes `contained`, not the proposed `suppressed` outcome. Keep explanation visible without an attack pulse. |
| Incomplete-result text and neutral styling | Phase 5: avoids automatically coloring every no-read outcome as contained. | The new style still treats any enforcement as sufficient when exploration is complete; multiple-session cases need a stronger classifier. The engine can also fail to flag pending work after a read, so the text fix alone is insufficient. |

Codex contributes one extra assertion for suppressed events. It does not add a dedicated regression fixture proving equal caps or browser tests for the revised result states. Its README's other-machine worktree path should not be copied as a local setup instruction.

## Claude: strengthen assumptions before comparison

| Change | Benefit and phase | Adaptation needed |
| --- | --- | --- |
| Five explicit CVE control entries | Phases 2 and 5: prevents reachable appliance findings from silently receiving generic no-coverage behavior. | All five are still missing on merged main. Review each entry's source, traffic path, deployment assumptions and applicability before adoption. A boolean mitigation entry is a simulation assumption, not proof of real-world WAF effectiveness. |
| Throw on missing modeled CVE coverage | Phases 2 and 5: exposes missing configuration instead of silently assigning a result. | Check the complete finding/control catalog at scenario validation or build time, before playback. Distinguish declared unknown/unsupported coverage from a missing declaration. Baseline and standalone-canary early returns currently bypass the lookup. Preserve Gemini's profile options when adapting the function. |
| Remove implicit interface defaults | Phase 1: avoids inventing HTTPS for invalid assets. | Useful cleanup at validated boundaries. `simulateEstate()` already validates nonempty interfaces, but generation and direct exported helper calls need their own explicit contracts. This does not validate protocol compatibility or topology coherence by itself. |
| Stable ordering or error for incomplete declared order | Phases 3 and 6: improves deterministic replay and exposes malformed scenarios. | Validate every declared ID eagerly, including duplicates, unknown IDs and omitted assets. Claude's implementation only checks ranks when a sort comparator runs; a single-asset scenario with an unrelated declared ID is accepted. |
| Realism review and sensitivity script | Planning across all six phases: explains causal weaknesses and supplies reproducible probes. | Preserve as baseline analysis with its revision label. Several probes assume the old engine and require replacement before use against Gemini. |

The five coverage entries are `CVE-2020-3452`, `CVE-2021-20016`, `CVE-2022-1040`, `CVE-2023-28771` and `CVE-2024-24919`. This review verified their absence/presence in code, not the external validity of each mitigation claim.

### Caveats in Claude's tests and diagnostic script

- The new coverage sweep checks sampled generated findings rather than exhaustively checking every declarable CVE. Its four HTTP-portal assertions accept either shielded or bypass outcomes, so they do not prove that a configured covered path actually blocks. Add precise covered/uncovered and non-HTTP fixtures.
- The incomplete-order test deliberately supplies two entries to trigger sorting. Add a single-asset counterexample and validate orders before traversal.
- `review-comparison.cjs` predates Gemini. Removing exercise findings now tests a removed mechanism. Comparing baseline with REvil SOC no longer establishes a no-signal condition because Gemini places telemetry on the estate.
- The script treats `canaryAssetId === null` as evidence of a signal without a decoy. Gemini records actual decoys in `estate.defensePosture.decoys` and leaves the singular legacy field null for those assets. Check event target IDs against deployed decoys instead.
- Retain fixed-trace and scope tests, but distinguish the legacy comparison fixtures from the engine actually called by the Wire UI. Passing one does not establish the other's correctness.

## Fresh targeted evidence

Both branch regression suites were rerun in isolated exports and passed. Read-only probes of the merged engine examined 80 seeds for each of mixed, demo and logs presets:

- The generated CVE findings encountered exactly the five missing coverage entries listed above.
- Across the 80 mixed estates with ARTEX, `simulateWireRun(estate, 'combined', 'artex')` emitted zero control lifecycle events; `soc-canary` emitted 249 control events in total. The number is an implementation observation, not an effectiveness statistic. The wrapper enables timed response only for `soc` and `soc-canary`; its canary telemetry path also omits `combined`. Some immediate boolean mitigations still operate in `combined`, so zero lifecycle events does not mean zero blocking.
- The merged validator accepted an incomplete declared action order. A separate probe loaded Claude's actual branch engine and confirmed that a single-asset scenario with an unrelated order ID also completes without its intended error.

## Gaps neither branch closes

1. **Enterprise generation:** neither adds coherent deployment archetypes or establishes that every generated product/version, route and permission combination makes operational sense.
2. **Weaknesses and breach paths:** Claude makes control declarations more complete, but does not establish CVE applicability or causal paths. Gemini's new path generation still needs that review.
3. **Attacker behavior:** neither supplies a richer policy than merged Gemini. Codex's comparison corrections should precede conclusions about attacker effectiveness.
4. **Historical animation:** neither repairs the fixed ARTEX final-stage timing or supplies causal worker scheduling. Preserve the stopwatch and historical context while fixing those mechanisms.
5. **Defense comparison:** neither exposes and correctly integrates canaries plus agentic SOC plus virtual patching in the active timed UI. This is required by the user's latest direction.
6. **Regeneration/replay:** Claude's ordering work helps, but neither proves stable random inputs, scenario preservation and replay across the revised combined controls. Neither fixes dense label collisions.

## Suggested incorporation order

1. Bring coverage declarations and eager estate/order validation into the phase 1–2 foundation, with focused fixtures and explicit assumptions.
2. Adapt Codex's equal-budget, suppressed-event and honest-result improvements as one coordinated engine/UI change.
3. Implement the full combined defense through shared control settings and one response lifecycle; test individual and combined controls on identical scenario inputs.
4. Continue the documented causal scheduling, historical-clock and layout work. Update the sensitivity probes to the current model and record revision, seeds and assumptions with results.

This review adds recommendations and test evidence only. No implementation, merge, commit or push of either branch is included.
