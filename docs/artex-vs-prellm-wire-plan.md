# Wire demo plan — three defenses before and after agentic AI

**Date:** 2026-11-15

**Scope:** The Wire diagram, its synthetic scenarios, and their documentation.

**Implementation:** `js/wire-engine.js`, `wire.html`, `scripts/test-wire-model.cjs`, [comparison notes](pre-llm-vs-artex-comparison.md), [Wire model documentation](wire_diagram_logic.md), and `README.md`.

## 1. Demo outcome

Show how **Virtual Patching**, **Agentic SOC**, and **Canaries** change the same security outcome as adversary workflows shift from **pre-2023 human-led operations** to **ARTEX-era agentic operations**. Compare what each workflow can cover in a fixed window, how much time defenders have to act on the same activity, and when each technology prevents access, detects a problem, or contains it.

Use one fixed, four-layer comparison estate with identical exposures, starting access, and protected data across runs. The protected outcome is the **first unauthorized read of a designated sensitive record**. A decoy is a separate asset or marker. Both profiles use the same underlying access rules. Pre-2023 operators already used scripts, automation, and valid credentials. The modeled difference in capability is how the workflow handles context-dependent decisions, manual handoffs, and concurrent work. Dates describe the two workflows used in the demo.

### The comparison view

Use two profile rows and four primary columns. Each cell shows whether the protected record was reached, the first alert and its time if applicable, and the effective block or containment time and reason. A selected cell opens its chronological trace. Include a combined run as an optional comparison against Agentic SOC with identical settings.

| Attacker workflow | Baseline | Virtual Patching | Agentic SOC | Canaries |
| --- | --- | --- | --- | --- |
| Pre-2023 human-led | Outcome without the three modeled controls | Edge block and rule coverage | Signal, response and outcome | Decoy alert and lead time |
| ARTEX & Friends | Outcome without the three modeled controls | Edge block and rule coverage | Signal, response and outcome | Decoy alert and lead time |

Show each option's change versus baseline **within the same profile and scenario**. Compare profiles **within the same column**. Use the controlled comparisons below when explaining what caused a difference.

## 2. Two controlled comparisons

| Comparison | Change | Hold fixed | Show |
| --- | --- | --- | --- |
| **Speed** | Retimestamp the same recorded attacker activity using the two pace settings | Estate, ordered attacker events, observable signals at corresponding milestones, control policy and response latencies | Time to first boundary crossing and to the protected outcome. Show a containment decision that wins at one pace and loses at the other. |
| **Capability** | Switch between two authored workflow traces at a common pace and time budget | Estate, available opportunities, starting access, objective, permissions, per-opportunity timings and defender settings | Opportunities reviewed by the cutoff, manual handoffs, work occurring concurrently and what the defender observes. |

For capability, use a small set of abstract service opportunities with pre-authored outcomes. Have the human-led trace reuse scripted checks and pass a context-dependent decision through an operator. Have the agentic trace show concurrent review of opportunities and a context-dependent continuation, with one case that still needs human review. Show which opportunities each trace covered by the same cutoff and whether the protected record was reached. Attribute differences to the authored workflow and keep the opportunity set available to both profiles.

Use a 45-second acceptance fixture with three opportunities, 15 seconds per review and the same 45-second duration for any required human handoff. The human-led trace reviews one and waits at a decision point. The agentic trace reviews three concurrently and also waits on the opportunity that requires human review. A second opportunity produces a protected read at 30 seconds in the agentic trace and is available to the human-led trace after its first handoff. With access to the record denied in the constrained case, both profiles end without a protected read. Label the review counts as scenario outcomes.

Use inert event data for both comparisons. Each trace declares candidate milestones, their prerequisite events, telemetry, rule-coverage labels and decoy interactions. Run defensive decisions over those events. Suppress a milestone when a prerequisite is blocked and keep independent events in the trace. Every run uses synthetic records and stays in the browser simulation. Keep real asset names, exploit steps, model-driven attack execution and network actions out of the comparison fixtures.

## 3. What each technology contributes

| Option | When it works | Limiting case to show |
| --- | --- | --- |
| **Virtual Patching** | An active rule at the monitored ingress blocks a covered event before it reaches the protected service. | An event outside the policy's coverage continues. In a second fixture, an active, matching rule blocks the same milestone at both paces. |
| **Agentic SOC** | Observable telemetry triggers a policy, and the authorized containment action becomes effective before the objective. | Show a late response and a no-signal case. Expose telemetry, decision or approval, and enforcement as distinct timestamps. Use the same response policy for both profiles. |
| **Canaries** | Interaction with an instrumented decoy generates an alert. Compare lead time for early and late placements. | An untouched decoy produces no alert. A triggered decoy alone detects activity. In the optional combined run, credit containment to the SOC action and show the decoy as the source of the earlier signal. |

Render reasons in the result, for example `RULE MATCH · BLOCKED AT EDGE`, `OUTSIDE RULE COVERAGE`, `NO MATCHING SIGNAL`, `CONTAINMENT EFFECTIVE AFTER DATA ACCESS`, or `DECOY TRIGGERED · ALERT ONLY`. Scope each effect to the events or identities it actually covers. A block or containment action can leave other authored activity in progress.

### Reference run — the same response wins and loses

These are **synthetic acceptance fixtures**. In the reference run, the virtual patch has no matching rule, the regular SOC signal occurs at the first boundary crossing, and the same pre-authorized action takes 60 modeled seconds from signal to effective enforcement. Both traces touch the same early decoy, whose signal identifies the same containable identity as the regular SOC signal. Times are elapsed from the first ingress event.

| Milestone | Pre-2023 pace | ARTEX-era pace |
| --- | ---: | ---: |
| Early decoy interaction, if enabled | 00:10:00 | 00:00:05 |
| First boundary crossing and regular SOC signal | 01:30:00 | 00:00:30 |
| Protected read in baseline | 02:00:00 | 00:01:20 |
| Agentic SOC becomes effective | 01:31:00 | 00:01:30 |
| Agentic SOC response margin | +29 min | −10 s |
| Agentic SOC using the early canary signal | 00:11:00 | 00:01:05 |

The expected outcomes are protected reads in both baseline and out-of-scope patch runs, prevention at the slower pace and late containment at the faster pace with Agentic SOC, and early alerts with protected reads in both Canaries-only runs. In the combined faster run, removing the decoy signal restores the late outcome. Keep the response policy, action scope and latency fixed for that comparison. A separate fixture where an active virtual patch blocks the ingress event demonstrates prevention even at the faster pace.

Compute the **response margin** as baseline time to first protected read minus effective response time for the same profile and trace. Compute detection lead time using the same baseline time minus the first control alert time. Show either measure as unavailable when a required timestamp is absent. If enforcement and the protected read share a timestamp, give the objective precedence unless the trace establishes that enforcement took effect first. Preserve an observed protected read even if containment succeeds later. Keep enough trace after the objective to show late response.

## 4. Evidence and presentation

- **Pre-2023 field context.** CrowdStrike reported mean breakout times of 98 minutes in 2021 and 84 minutes in 2022 for interactive eCrime. The interval starts at initial host compromise and ends at first lateral movement to another host. Mandiant reported 2022 median dwell of 16 days across its investigations, from compromise to discovery. Keep dwell in the source notes. [CrowdStrike 2023 Global Threat Report, p. 9](https://www.crowdstrike.com/wp-content/uploads/2023/05/CrowdStrike2023GlobalThreatReport.pdf#page=9) · [Mandiant M-Trends 2023 findings](https://cloud.google.com/blog/transform/m-trends-2023-lessons-cyberattack-frontlines)
- **2023 onward field context.** CrowdStrike reported a 62-minute mean eCrime breakout and a fastest observed time of 2 minutes 7 seconds for 2023. That series describes observed breakout speed. Anthropic's 2025 case report illustrates an agent doing substantial tactical work with human supervision at critical decisions. Use the case as evidence of orchestration and concurrency. It supplies no comparable average time to a protected read and neither source quantifies the contribution of AI to the breakout trend. [CrowdStrike 2024 Global Threat Report overview](https://www.crowdstrike.com/en-us/blog/crowdstrike-2024-global-threat-report/) · [Anthropic campaign report](https://www.anthropic.com/news/disrupting-AI-espionage)
- **Local ARTEX reference.** The repo's guide reports approximately 75 seconds of ARTEX deliberation for a four-hop lab run. Label it as the guide's local figure. Before publishing any benchmark, capture repeat runs with explicit start and end events, model and hardware, and report the sample size and range. [ARTEX executive demo guide](artex_executive_demo_guide.md)
- **Wire results.** Label fixture times and effects as modeled. Show the same event endpoints and units when calculating a speed difference. Keep historical breakout, dwell, lab duration, and Wire scenario time in separately labeled fields. Avoid speed ratios between these sources. Show seconds in the clock and use one playback control for both profiles, with pause and skip to results. Display simulated timestamps independently of animation duration.

## 5. Implementation order

1. **Build the fixed comparison first.** The current estate schema is v3. The current `simulateEstate(estate, mode)` chooses a defense posture and the Wire stopwatch toggle changes displayed timings. Define a named comparison fixture using the existing graph and validation rules, plus a comparison evaluator for timestamped events. Keep fixture selection, pace and defense outside estate generation. Preserve the existing `simulateEstate` call and saved estate compatibility. Keep the generated and mixed estate views available for exploration.
2. **Build the defensive controls and summary.** Evaluate rule eligibility, signal availability, decoy interaction and effective enforcement explicitly. Drive the trace, matrix, and SOC tickets from the same event results. Add a standalone Canaries option and retain the existing combined path for the optional comparison. Grade by protected-record outcome, then show interception point, detection lead time and response margin where available. Expose the assumptions behind the selected cell.
3. **Add the capability comparison and verify the demo.** Author both capability traces against the shared fixture. Lead the walkthrough with the same-signal timing race, follow with the covered virtual patch and the canary-signal comparison, then show what concurrent, context-dependent work changes under a fixed time budget. Document evidence and fixture limits in the comparison notes and sync the README's scenario names and Wire model documentation.
4. **Defer broad catalog expansion and the infrastructure editor.** Add a service or identity role in the first release only if the two comparisons require it. Revisit broader technology coverage and an `Add Infra` editor after the fixed demo passes acceptance. Custom estates can remain an exploratory mode with their own results.

## 6. Acceptance

- Run `node scripts/test-wire-model.cjs`. Add deterministic assertions that mode and profile switches preserve the comparison estate and objective, the pace test uses identical ordered activity and changes the response race, and the capability test uses the same pace, budget and access rules. Verify repeated runs produce the same results.
- Cover patch match and miss, SOC signal absent and response before, at and after the objective, early, late and untouched decoys, alert-only behavior, and the added effect of a decoy signal with the same SOC policy. Exercise a scope mismatch where containment leaves an unrelated event in progress.
- Browser-check all eight primary cells and the optional combined run. Confirm that cell detail, trace, stopwatch and tickets agree. Verify profile and scenario swaps mid-playback clear the previous run's timers and tickets, and check comparison and controls at desktop and narrow widths.
- The walkthrough passes when a viewer can identify what changed in attacker capability and speed, which of the three options changed detection or impact, and which assumptions determined the outcome.

## 7. Implementation audit — 2026-11-15

- **Containment timing.** The Access Denied exercise credited SOC with prevention even though access policy denied the read and scheduled containment fell after the 45-second cutoff. Record effective enforcement when it occurs and show any later scheduled time separately.
- **Graph and SOC ticker.** A covered patch suppressed downstream events, but the graph drew them as successful paths and the ticker showed a protected read. Keep suppressed events in the trace with their reason. Use observed events for the graph and ticker.
- **Combined comparison.** The comparison labeled SOC + Canary also enabled Virtual Patching. Apply the same SOC policy as the standalone SOC column with the canary signal added. Keep Exploratory Infra’s separate Defense-in-Depth posture available.
- **Playback on column change.** Hiding Combined while it was selected left the clock and end time from the old run. Reset playback when the selection falls back to SOC and rebuild its clock, graph and tickets from the new trace.

**Status:** All four fixes verified with the model regression suite and headless Chrome. Checks covered all ten comparison cells, profile and fixture switches during playback, and the selector and covered-patch result at 390 px.
