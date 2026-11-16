# Project intent and rules for future changes

This guidance records the user's six-phase product model, supplied on 16 November 2026. Use it when planning, implementing, reviewing and testing fixes. The product is an animated enterprise attack-and-defense demonstration with historically informed timing. Preserve that purpose as the simulation becomes more coherent.

## Six phases

1. **Build a plausible enterprise.** Generate example infrastructure from likely hardware and software objects, connected in ways that make operational sense. Include ingress, identity, applications/services and data stores as appropriate to a coherent enterprise archetype. Model product/version, interfaces, protocols, trust boundaries, service dependencies and access relationships. A visually connected diagram must not imply arbitrary access between unrelated systems.
2. **Assign applicable weaknesses and a credible breach path.** Map CVEs to matching products, versions and configurations; record KEV catalog membership separately, because not every CVE is a KEV. Include explicit misconfigurations and credential/permission weaknesses where appropriate. Provide an unprotected or badly configured example in which prerequisites form a viable route to sensitive data. Label deliberately authored vulnerable walkthroughs; do not bypass normal access checks or force every generated estate to be breachable.
3. **Model attacker behavior.** Demonstrate how a pre-2023 gang-style operator or an ARTEX-like attacker would attack that same enterprise. Explain initial access, discovery, credentials, lateral movement and data access through the actual modeled assets and prerequisites. Named gang presets should reflect documented behavior where available; distinguish historical reconstruction from a historical-style attacker applied to a modern estate. Both attacker types may succeed or fail depending on the environment and defenses.
4. **Animate with a historical clock.** Animate the attack flow and display a stopwatch of cumulative modeled elapsed time informed by historical attack data. Preserve this as a core feature. Document sources and the milestones they measure; separate reported facts from assumed stage allocations. Animation playback speed and local runtime must not be presented as field attack duration. Keep the clock and visible sequence consistent with action prerequisites, telemetry, intervention and impact.
5. **Compare defenses on the same enterprise.** Required comparisons are (a) baseline, (b) virtual patching, (c) agentic SOC, and (d) canaries together with both agentic SOC and virtual patching. The final case means all three controls enabled. Standalone canary and SOC-plus-canary modes may remain useful additional comparisons, but do not substitute for that full combination. Show how control coverage and intervention change the animated route, timing and result. A canary supplies evidence; containment requires a response. Preserve data reads that occurred before containment. Use equal exploration allowances and shared scenario assumptions; defense outcomes must have a causal explanation.
6. **Regenerate and replay.** Allow the user to spawn a new plausible infrastructure and replay the various attacker/defense flows. Changing an attacker or defense must retain the current enterprise, weaknesses and relevant underlying random inputs for comparison. Replay must reproduce the same inputs and event history. New Infra creates a new scenario; layout changes and Results must not silently create one.

## How to apply this guidance

- Treat the phases as a dependency order: coherent infrastructure, applicable weaknesses, attack policy, timed animation, defense comparison, then regeneration/replay integration. Fix downstream symptoms without weakening upstream correctness.
- Preserve an engaging, readable walkthrough. Improve explanatory fidelity without replacing the demo with only a benchmark, a report or an unanimated engine.
- For each proposed change, identify the affected phases, its user-visible effect and acceptance checks. Verify that topology, findings, access checks, animation, stopwatch, tickets and final summary describe the same run.
- Keep incomplete exploration, prevention, alerting, containment and impact distinct. Do not give a defense credit for a display cap, missing path or predetermined timing advantage.
- Consult this file before older design documents. It records the latest user direction and takes precedence where older plans conflict. The detailed engineering specification and remediation plan remain supporting documents, not reasons to remove historical timing or the six-phase experience.
- The documented merge review and subsequent planning are documentation work until implementation is requested. This guidance itself does not request a code change, push or deployment.

## Supporting plans

- [Post-merge remediation plan](docs/gemini-merge-remediation-plan.md)
- [Detailed engineering specification](docs/wire-improvement-engineering-spec.md)
