# Design reference implementation plan

Reference: user-supplied `Screenshot 2026-11-16 132753.png`, 16 November 2026.

Status: implemented and verified locally. The simulation engine is unchanged by this refresh.

## Design decisions

- Match the charcoal Range Operations shell, compact header, cyan selection borders, muted slate defense cards and restrained typography.
- Put an accessible ARTEX / Pre-LLM Attacks toggle in the header in place of the attacker dropdown. It changes the attack policy on the same estate.
- Expose four defense cards: Baseline, Virtual Patch, Agentic SOAR and Defense-in-Depth. The final card combines patching + SOC + deployed canaries. Remove standalone Canary and SOC-plus-Canary cards from the presentation; retain engine modes for fixtures.
- Use small green markers for untouched assets. Successful attacks use conspicuous pink concentric halos, dashed pink paths and visible vulnerability callouts. Keep prevented actions amber, containment cyan and decoy alerts gold, with text labels so color is not the only cue.
- Quiet the unused topology, make focused/active paths prominent, and use deterministic staggered placement with reserved callout space. Preserve keyboard details, readable scrolling, historical-context stopwatch, replay and new-estate behavior.
- Add a functional canvas search control corresponding to the screenshot's magnifier, with matching assets and adjacent connections highlighted.

## Implementation sequence

1. Replace the accumulated inline stylesheet with one cohesive stylesheet and rebuild the header/control markup.
2. Wire attacker selection, four defense cards and run-status context to the existing model. Keep engine behavior unchanged.
3. Update node placement, state cues, CVE badges and search/focus behavior; handle resize without regenerating the estate.
4. Update structural and browser checks for the new controls. Verify both attackers and all four visible defense modes, replay/Results, New Infra, search, keyboard access, reduced motion and desktop/narrow layouts. Measure labels and visible callouts for collisions, capture screenshots and compare them visually with the reference.

## Acceptance

The four defense cards and two attacker choices are visible and keyboard operable; standalone canary is absent. Changing either selection reuses the current estate and matching replay inputs. Selected controls have a clear visual and accessible state. The clock and result remain truthful; baseline copy must not promise a breach when no viable path exists. Active, prevented, contained and alerted events have distinct cues and legible callouts. No application engine changes are required for this visual refresh.

## Verification evidence

- `node scripts/test-wire-model.cjs` and `node scripts/test-remediation.cjs` pass.
- Browser checks pass for 72 combinations: two attacker choices × four visible defenses × seeds 1/42/99 × 1440 × 900, 1280 × 720 and 390 × 844 viewports.
- Verified title-toggle selected/accessibility state, absence of the supplementary canary cards, Results and deterministic replay, unchanged estates across comparisons, New Infra, functional search and Escape dismissal, keyboard details and attacker selection, actual animation progression, reduced-motion styling, and no browser page errors.
- Measured persistent labels and visible vulnerability callouts have no cross-asset collisions in the tested cases. Added a direct check that baseline attack halos do not obscure their own labels, and that settled success markers use the intended pink state color.
- Baseline, layered-defense and narrow-screen screenshots were captured; the baseline and desktop rendering were visually inspected against the supplied reference. State-color transitions are allowed to settle before screenshot/color assertions.
- `git diff --check` passes. No engine behavior, remote publication or external service is needed for the design changes.

The canvas keeps horizontal/vertical scrolling for dense estates; the supplied screenshot also shows a wider infrastructure than the visible crop. Quiet topology remains available through search or asset focus. Gold diamond/dashed-ring decoy alerts differ from amber prevention and cyan containment, with accompanying text labels.
